#pragma once

#include <atomic>
#include <cstdint>
#include <iostream>
#include <memory>
#include <type_traits>
#include <exception>
#include <functional>

#include <dlfcn.h>
#include <immintrin.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define PAGE_SIZE   4096
#define CHAN_SIZE   4096
#define PROXY_LOG(c) std::cerr

constexpr int  kSHMAlignment = 8;

class ParentTerminated: public std::exception {};
class ChildTerminated: public std::exception {};
class OperationFailed: public std::exception {};

bool parent_terminated = false;
bool child_terminated = false;

enum DCODE {
    kDCode_Init,
    kDCode_Limit,
    kDCode_Shutdown,
    kDCode_Task,
};

enum ChannelStatus {
    kOpen,
    kClosed,
};

enum ChannelSide {
    kParent,
    kChild,
};

constexpr uint32_t kSegmentMagic = 0xc7390fbc;

template <typename Tuple, std::size_t ... Is>
auto pop_front_impl(const Tuple& tuple, std::index_sequence<Is...>)
{
    return std::make_tuple(std::get<1 + Is>(tuple)...);
}

template <typename Tuple>
auto pop_front(const Tuple& tuple)
{
    return pop_front_impl(tuple,
                          std::make_index_sequence<std::tuple_size<Tuple>::value - 1>());
}

class Channel {
public:
    friend class SegmentDescriptor;
    Channel(std::size_t sz)
    {
        base_ = mmap(nullptr, sz,
                     PROT_READ  | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (base_ == MAP_FAILED)
            PROXY_LOG(ERROR) << "Cannot create shared memory for channel";
    }

    void* GetBase()
    {
        return base_;
    }

private:
    uint64_t      size_;
    void*         base_;
    ChannelStatus status_;
#ifdef PROXY_DBG
    uint32_t      canary = 0xdeadbeaf;
#endif
};

class Segment {
public:
    friend class SegmentDescriptor;

    Segment(std::size_t chan_sz)
        : turn_{kParent},
          send_{chan_sz},
          recv_{chan_sz}
    {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
        pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
        pthread_mutex_init(&mtx_, &attr);
    }

    __always_inline
    bool ParentTurn() { return turn_ == kParent; }
    __always_inline
    bool ChildTurn() { return !ParentTurn(); }

private:
    // XXX: use a ring queue so that we can have multiple requests queued at the same time.
    volatile ChannelSide turn_;
    pthread_mutex_t      mtx_;
    Channel              send_;
    Channel              recv_;
    uint32_t             magic_ = kSegmentMagic;
};

class SegmentDescriptor {
public:
    SegmentDescriptor(ChannelSide side, Segment& seg)
        : side_{side},
          segment_{seg}
    {
        GetSendChannel().status_ = kOpen;
    }

    ~SegmentDescriptor()
    {
        GetSendChannel().status_ = kClosed;
    }

    Channel& GetSendChannel() const
    {
        return ((side_ == kParent) ? segment_.send_ : segment_.recv_);
    }

    Channel& GetRecvChannel() const
    {
        return ((side_ == kParent) ? segment_.recv_ : segment_.send_);
    }

    static __always_inline void
    Lock(pthread_mutex_t& mtx)
    {
        int rc;
        rc = pthread_mutex_lock(&mtx);
        if (rc == EOWNERDEAD) {
            /**
             * Another process has dies while holding this mutex.
             * We should clean up after that process, and unlock
             * them mutex when we are done with it.
             */
            // CLEANUP_THE_STATE();
            /**
             * Tell the runtime that we have taken care of the
             * situation.
             */
            rc = pthread_mutex_consistent(&mtx);
            if (rc)
                PROXY_LOG(ERROR) << "Failed: Cannot make the mutex consistent!";
            else
                PROXY_LOG(ERROR) << "Mutex recovered";
        } else if (rc == ENOTRECOVERABLE) {
                PROXY_LOG(ERROR) << "Failed: Another process has failed to recover " \
                                    "the mutex and mark it consistent.";
        } else if (rc) {
                PROXY_LOG(ERROR) << "Failed.";
        }
    }

    /**
     * @internal Unlock the PSHARED / ROBUST mutex.
     */
    static __always_inline void
    Unlock(pthread_mutex_t& mtx)
    {
        int rc = pthread_mutex_unlock(&mtx);
        if (rc == EPERM) {
            PROXY_LOG(ERROR) << "Cannot unlock mutex: EPERM";
            exit(1);
        } else if (rc == EINVAL) {
            PROXY_LOG(ERROR) << "Cannot unlock mutex: EINVAL";
            exit(1);
        }
    }


    bool VerifyIntegrity() const
    {
        return segment_.magic_ == kSegmentMagic;
    }

    void Wait()
    {
        if (side_ == kParent) {
            while(segment_.turn_ == kChild) {
                _mm_pause();
                usleep(100000);
                if (child_terminated) {
                    segment_.turn_ = kParent;
                    throw ChildTerminated{};
                }
            }
        } else if (side_ == kChild) {
            while(segment_.turn_ == kParent) {
                _mm_pause();
                usleep(100000);
                if ((parent_terminated = (getppid() == 1))) {
                    throw ParentTerminated{};
                }
            }
        }
    }

    void Switch()
    {
        segment_.turn_ = (segment_.turn_ == kParent) ? kChild : kParent;
    }

    Segment& GetSegment() const
    {
        return segment_;
    }

private:
    ChannelSide side_;
    Segment&    segment_;
};


class Stub {
public:
    Stub(std::size_t chan_sz)
        : chan_sz_{chan_sz}
    { }

    template <typename... Args>
    void
    CreateRequest(void* base, Args... args) {
        Unroll(base, args...);
    }

    template <typename T, typename... Args>
    void
    Unroll(void* base, T t, Args... args)
    {
        std::size_t offset;
        if constexpr (std::is_same<T, std::string>::value) {
            char* base_param = static_cast<char*>(base);
            strcpy(base_param, t.c_str());
            std::string::size_type strlen = t.size();
            base += strlen;
            chan_sz_ -= strlen;
            auto ret = std::align(kSHMAlignment, 1, base, chan_sz_);
            if (ret == nullptr)
                throw 22;
        } else {
            T* base_param = static_cast<T*>(base);
            *base_param = t;
            base += sizeof(T);
            chan_sz_ -= sizeof(T);
            auto ret = std::align(kSHMAlignment, 1, base, chan_sz_);
            if (ret == nullptr)
                throw 22;
        }

        if constexpr (sizeof...(args) > 0)
            Unroll(base, args...);
    }

    template <typename R>
    R
    ParseResult(void* base) {
        if constexpr (std::is_same<R, std::string>::value) {
            char* result = static_cast<char*>(base);
            return std::string{result};
        } else {
            R* result = static_cast<R*>(base);
            return *result;
        }
    }

private:
    std::size_t chan_sz_;
};

extern "C"
void sig_handler(int signo);

extern "C"
void
sig_handler(int signo)
{
    child_terminated = true;
}

template <typename SERV>
class Proxy {
private:
    using RET = std::tuple_element_t<0, typename SERV::request_type>;
public:
    using func_type = int (*)(std::tuple<int, int>);

    Proxy(std::size_t chan_sz)
        : service_{},
          stub_{chan_sz},
          chan_sz_{chan_sz}
    {
        static_assert(sizeof(Segment) <= PAGE_SIZE);
        void* m = mmap(nullptr, PAGE_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, 0, 0);
        if (!m)
            PROXY_LOG(ERROR) << "Cannot create shared memory for segment";
        Segment* seg = new (m) Segment{chan_sz};
        parent_terminated = false;
        child_terminated = false;
        pid_t pid = fork();
        if (pid == 0) {
            segd_ = std::make_unique<SegmentDescriptor>(kChild, *seg);
            ServiceLoop();
        } else if (pid > 0) {
            InstallSignalHandlers();
            segd_ = std::make_unique<SegmentDescriptor>(kParent, *seg);
        } else
            PROXY_LOG(ERROR) << "fork() failed: ";
        
    }

    ~Proxy()
    {}

    template <typename... Args>
    RET
    Execute(Args... args)
    {
        void* base = segd_->GetSendChannel().GetBase();
        stub_.CreateRequest(base, args...);
        segd_->Switch();
        try {
            segd_->Wait();
        } catch (ChildTerminated& cte) {
            std::cerr << "Child died" << std::endl;
            throw OperationFailed{};
        }
        RET result = stub_.template ParseResult<RET>(segd_->GetRecvChannel().GetBase());
        return result;
    }

private:
    void
    InstallSignalHandlers() {
        struct sigaction sa;
        sa.sa_handler = sig_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        if (sigaction(SIGCHLD, &sa, nullptr) < 0)
            throw 111;
    }

    template <int N, typename TUP>
    void
    ExtractElem(TUP& instance, void*& recv) {
        if constexpr (std::tuple_size<TUP>::value >= N + 1)
        {
            using TYPE = std::tuple_element_t<N, TUP>;
            std::size_t offset;
            if constexpr (std::is_same<TYPE, std::string>::value) {
                char* item = static_cast<char*>(recv);
                std::cerr << "got paramXXX: " << item << std::endl;
                std::string tmp {item};
                std::get<N>(instance) = tmp;
                recv += tmp.size();
                chan_sz_ -= tmp.size();
                auto ret = std::align(kSHMAlignment, 1, recv, chan_sz_);
                if (ret == nullptr)
                    throw 44;
            } else {
                std::add_pointer_t<TYPE> p0;
                auto item = static_cast<decltype(p0)>(recv);
                std::cerr << "got paramYYY: " << *item << std::endl;
                std::get<N>(instance) = *item;
                recv += sizeof(item);
                chan_sz_ -= sizeof(item);
                auto ret = std::align(kSHMAlignment, 1, recv, chan_sz_);
                if (ret == nullptr)
                    throw 55;
            }
        }
    }

    template <typename T>
    auto
    ExtractParams(void* recv) {
        T tup;
        static_assert(std::tuple_size<T>::value <= 17);
        ExtractElem<1> (tup, recv);
        ExtractElem<2> (tup, recv);
        ExtractElem<3> (tup, recv);
        ExtractElem<4> (tup, recv);
        ExtractElem<5> (tup, recv);
        ExtractElem<6> (tup, recv);
        ExtractElem<7> (tup, recv);
        ExtractElem<8> (tup, recv);
        ExtractElem<9> (tup, recv);
        ExtractElem<10>(tup, recv);
        ExtractElem<11>(tup, recv);
        ExtractElem<12>(tup, recv);
        ExtractElem<13>(tup, recv);
        ExtractElem<14>(tup, recv);
        ExtractElem<15>(tup, recv);
        ExtractElem<16>(tup, recv);
        return tup;
    }

    template <typename T>
    void
    PutResult(T& tup, void* snd) {
        using TYPE = std::tuple_element_t<0, T>;
        std::size_t offset;
        if constexpr (std::is_same<TYPE, std::string>::value) {
            char* result = static_cast<char*>(snd);
            strcpy(result, std::get<0>(tup).c_str());
        } else {
            std::add_pointer_t<TYPE> result;
            result = static_cast<decltype(result)>(snd);
            *result = std::get<0>(tup);
        }
    }

        void ServiceLoop()
    {
        while (true) {
            try {
                segd_->Wait();
            } catch (ParentTerminated& pte) {
                std::cerr << "Parent died" << std::endl;
                exit(1);
            }
            using RQ = typename SERV::request_type;
            RQ ins = ExtractParams<RQ>(segd_->GetRecvChannel().GetBase());
            service_.Handle(ins);
            PutResult(ins, segd_->GetSendChannel().GetBase());
            segd_->Switch();
        }
    }
    std::unique_ptr<SegmentDescriptor> segd_;
    SERV service_;
    Stub stub_;
    void* handle_;
    std::size_t chan_sz_;
};

template <typename RQ>
class ProxySO {
private:
    using RET = std::tuple_element_t<0, RQ>;
public:
    using func_type = int (*)(std::tuple<int, int>);

    ProxySO(std::size_t chan_sz, std::string soname)
        : stub_{chan_sz},
          chan_sz_{chan_sz}
    {
        handle_ = dlopen(soname.c_str(), RTLD_LOCAL | RTLD_NOW);
        if (!handle_) {
            std::cerr << "failed to open lib" << std::endl;
            exit(1);
        }

        static_assert(sizeof(Segment) <= PAGE_SIZE);
        void* m = mmap(nullptr, PAGE_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, 0, 0);
        if (!m)
            PROXY_LOG(ERROR) << "Cannot create shared memory for segment";
        Segment* seg = new (m) Segment{chan_sz};
        parent_terminated = false;
        child_terminated = false;
        pid_t pid = fork();
        if (pid == 0) {
            segd_ = std::make_unique<SegmentDescriptor>(kChild, *seg);
            ServiceLoop();
        } else if (pid > 0) {
            InstallSignalHandlers();
            segd_ = std::make_unique<SegmentDescriptor>(kParent, *seg);
        } else
            PROXY_LOG(ERROR) << "fork() failed: ";
        
    }

    ~ProxySO()
    {}

    template <typename... Args>
    RET
    Execute(Args... args)
    {
        void* base = segd_->GetSendChannel().GetBase();
        stub_.CreateRequest(base, args...);
        segd_->Switch();
        try {
            segd_->Wait();
        } catch (ChildTerminated& cte) {
            std::cerr << "Child died" << std::endl;
            throw OperationFailed{};
        }
        RET result = stub_.template ParseResult<RET>(segd_->GetRecvChannel().GetBase());
        return result;
    }

private:
    void
    InstallSignalHandlers() {
        struct sigaction sa;
        sa.sa_handler = sig_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        if (sigaction(SIGCHLD, &sa, nullptr) < 0)
            throw 111;
    }

    template <int N, typename TUP>
    void
    ExtractElem(TUP& instance, void*& recv) {
        if constexpr (std::tuple_size<TUP>::value >= N + 1)
        {
            using TYPE = std::tuple_element_t<N, TUP>;
            std::size_t offset;
            if constexpr (std::is_same<TYPE, std::string>::value) {
                char* item = static_cast<char*>(recv);
                std::cerr << "got paramAAA: " << item << std::endl;
                std::string tmp {item};
                std::get<N>(instance) = tmp;
                offset = tmp.size();
                offset = ((offset / kSHMAlignment) + 1) * kSHMAlignment;
            } else {
                std::add_pointer_t<TYPE> p0;
                auto item = static_cast<decltype(p0)>(recv);
                std::cerr << "got paramBBB: " << *item << std::endl;
                offset = kSHMAlignment;
                std::get<N>(instance) = *item;
            }
            recv += offset;
        }
    }

    template <typename T>
    auto
    ExtractParams(void* recv) {
        T tup;
        static_assert(std::tuple_size<T>::value <= 17);
        ExtractElem<1> (tup, recv);
        ExtractElem<2> (tup, recv);
        ExtractElem<3> (tup, recv);
        ExtractElem<4> (tup, recv);
        ExtractElem<5> (tup, recv);
        ExtractElem<6> (tup, recv);
        ExtractElem<7> (tup, recv);
        ExtractElem<8> (tup, recv);
        ExtractElem<9> (tup, recv);
        ExtractElem<10>(tup, recv);
        ExtractElem<11>(tup, recv);
        ExtractElem<12>(tup, recv);
        ExtractElem<13>(tup, recv);
        ExtractElem<14>(tup, recv);
        ExtractElem<15>(tup, recv);
        ExtractElem<16>(tup, recv);
        return tup;
    }

    template <typename T>
    void
    PutResult(T& tup, void* snd) {
        std::add_pointer_t<std::tuple_element_t<0, T>> result;
        result = static_cast<decltype(result)>(snd);
        *result = std::get<0>(tup);
    }

    void ServiceLoop()
    {
        while (true) {
            try {
                segd_->Wait();
            } catch (ParentTerminated& pte) {
                std::cerr << "Parent died" << std::endl;
                exit(1);
            }
            RQ ins = ExtractParams<RQ>(segd_->GetRecvChannel().GetBase());
            auto func = (func_type)dlsym(handle_, std::get<1>(ins).c_str());
            if (!func) {
                std::cerr << "failed to lookup func" << std::endl;
                exit(3);
            }
            std::get<0>(ins) = func(pop_front(pop_front(ins)));
            PutResult(ins, segd_->GetSendChannel().GetBase());
            segd_->Switch();
        }
    }
    std::unique_ptr<SegmentDescriptor> segd_;
    Stub stub_;
    void* handle_;
    std::size_t chan_sz_;
};
