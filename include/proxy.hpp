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

template<std::size_t SZ> class SegmentDescriptor;

template <std::size_t SZ>
class Channel {
public:
    friend class SegmentDescriptor<SZ>;
    Channel(std::size_t sz)
    {
        base_ = mmap(nullptr, sz,
                     PROT_READ  | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (base_ == MAP_FAILED)
            PROXY_LOG(ERROR) << "Cannot create shared memory for channel";
    }

    operator void* ()
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

template<std::size_t SZ>
class Segment {
public:
    friend class SegmentDescriptor<SZ>;

    Segment()
        : turn_{kParent},
          send_{SZ},
          recv_{SZ},
          chan_sz_{SZ}
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
        ExtractElem<0> (tup, recv);
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
        return tup;
    }

private:
    // XXX: use a ring queue so that we can have multiple requests queued at the same time.
    volatile ChannelSide turn_;
    pthread_mutex_t      mtx_;
    Channel<SZ>          send_;
    Channel<SZ>          recv_;
    uint32_t             magic_ = kSegmentMagic;
    std::size_t          chan_sz_;
};

template<std::size_t SZ>
class SegmentDescriptor {
public:
    template <typename... Args>
    void
    SendRequest(Args... args) {
        Unroll(GetSendChannel(), SZ, args...);
        Switch();
    }

    template <typename T, typename... Args>
    void
    Unroll(void* base, std::size_t chan_sz, T t, Args... args)
    {
        std::size_t offset;
        if constexpr (std::is_same<T, std::string>::value) {
            char* base_param = static_cast<char*>(base);
            strcpy(base_param, t.c_str());
            std::string::size_type strlen = t.size();
            base += strlen;
            chan_sz -= strlen;
            auto ret = std::align(kSHMAlignment, 1, base, chan_sz);
            if (ret == nullptr)
                throw 22;
        } else {
            T* base_param = static_cast<T*>(base);
            *base_param = t;
            base += sizeof(T);
            chan_sz -= sizeof(T);
            auto ret = std::align(kSHMAlignment, 1, base, chan_sz);
            if (ret == nullptr)
                throw 22;
        }

        if constexpr (sizeof...(args) > 0)
            Unroll(base, chan_sz, args...);
    }

    template <typename T>
    auto
    ExtractParams() {
        Wait();
        return segment_.template ExtractParams<T>(GetRecvChannel());
    }

    template <typename T>
    void
    PutResult(T& tup) {
        segment_.template PutResult<T>(tup);
        Switch();
    }

    Channel<SZ>& GetSendChannel() const
    {
        return ((side_ == kParent) ? segment_.send_ : segment_.recv_);
    }

    Channel<SZ>& GetRecvChannel() const
    {
        return ((side_ == kParent) ? segment_.recv_ : segment_.send_);
    }

    SegmentDescriptor(ChannelSide side, Segment<SZ>& seg)
        : side_{side},
          segment_{seg}
    {
        GetSendChannel().status_ = kOpen;
    }

    ~SegmentDescriptor()
    {
        GetSendChannel().status_ = kClosed;
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
    { segment_.turn_ = (segment_.turn_ == kParent) ? kChild : kParent; }
   
    Segment<SZ>& GetSegment() const
    {
        return segment_;
    }

private:
    ChannelSide     side_;
    Segment<SZ>&    segment_;
};


template<std::size_t SZ>
class Stub {
public:
    Stub(std::shared_ptr<SegmentDescriptor<SZ>> seg)
        : chan_sz_{SZ},
          segd_{seg}
    { }

    template <typename... Args>
    void
    SendRequest(Args... args) {
        segd_->SendRequest(args...);
    }

    template <typename R>
    auto
    ExtractParams() {
        auto rt = segd_->template ExtractParams<std::tuple<R>>();
        R r = std::get<0>(rt);
        // std::cerr << "r: " << r << std::endl;
        // void* base = segd_->GetRecvChannel();
        // try {
        //     segd_->Wait();
        // } catch (ChildTerminated& cte) {
        //     std::cerr << "Child died" << std::endl;
        //     throw OperationFailed{};
        // }
        return r;
    }

private:
    std::size_t chan_sz_;
    std::shared_ptr<SegmentDescriptor<SZ>> segd_;
};

extern "C"
void sig_handler(int signo);

extern "C"
void
sig_handler(int signo)
{
    child_terminated = true;
}

class BaseProxy {};


template<typename T>
struct remove_first_type
{
};

template<typename T, typename... Ts>
struct remove_first_type<std::tuple<T, Ts...>>
{
    using type = std::tuple<Ts...>;
};


template <typename SUB, std::size_t SZ>
class AbstractProxy: public BaseProxy {
protected:

    AbstractProxy()
        : chan_sz_{SZ}
    {
        this->Init();
    }

    void Init()
    {
        static_assert(sizeof(Segment<SZ>) <= PAGE_SIZE);

        void* m = mmap(nullptr, PAGE_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, 0, 0);
        if (!m)
            PROXY_LOG(ERROR) << "Cannot create shared memory for segment";
        Segment<SZ>* seg = new (m) Segment<SZ>{};
        parent_terminated = false;
        child_terminated = false;
        pid_t pid = fork();
        if (pid == 0) {
            segd_ = std::make_unique<SegmentDescriptor<SZ>>(kChild, *seg);
            side_ = kChild;
        } else if (pid > 0) {
            InstallSignalHandlers();
            segd_ = std::make_shared<SegmentDescriptor<SZ>>(kParent, *seg);
            stub_ = std::make_unique<Stub<SZ>>(segd_);
            side_ = kParent;
        } else
            PROXY_LOG(ERROR) << "fork() failed: ";
    }

    void
    InstallSignalHandlers() {
        struct sigaction sa;
        sa.sa_handler = sig_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        if (sigaction(SIGCHLD, &sa, nullptr) < 0)
            throw 111;
    }

    template<typename RET, typename... Args>
    void
    StartServiceLoop()
    {
        while (true) {
            try {
                auto ins = this->segd_->template ExtractParams<std::tuple<Args...>>();
                RET result = static_cast<SUB*>(this)->template Do<RET>(ins);
                this->segd_->SendRequest(result);
            } catch (ParentTerminated& pte) {
                std::cerr << "Parent died" << std::endl;
                exit(1);
            }
        }
        __builtin_unreachable();
    }

    template<typename RET, typename... Args>
    void
    StartServiceLoopForChild() {
        if (side_ == kChild)
            StartServiceLoop<RET, Args...>();
    }

public:
    template <typename RET, typename... Args>
    RET
    Execute(Args... args)
    {
        this->StartServiceLoopForChild<RET, Args...>();
        stub_->SendRequest(args...);
        RET result = stub_->template ExtractParams<RET>();
        return result;
    }

protected:
    std::shared_ptr<SegmentDescriptor<SZ>> segd_;
    std::unique_ptr<Stub<SZ>> stub_;
    void* handle_;
    std::size_t chan_sz_;
    ChannelSide side_;
};

template <std::size_t SZ, typename SERV>
class ProxyDirect final: public AbstractProxy<ProxyDirect<SZ, SERV>, SZ> {
public:
    ProxyDirect()
        : AbstractProxy<ProxyDirect, SZ>{},
          service_{}
    {
    }

    ~ProxyDirect()
    {}

    template<typename RET, typename REQ>
    RET
    Do(REQ& ins)
    {
        return service_.Handle(ins);
    }

private:
    SERV service_;
};

template <std::size_t SZ>
class ProxySO final: public AbstractProxy<ProxySO<SZ>, SZ> {
public:
    ProxySO(std::string soname)
        : AbstractProxy<ProxySO, SZ>{}
    {
        handle_ = dlopen(soname.c_str(), RTLD_LOCAL | RTLD_NOW);
        if (!handle_) {
            std::cerr << "failed to open lib" << std::endl;
            exit(1);
        }
    }

    ~ProxySO()
    {}

    template<typename RET, typename REQ>
    RET
    Do(REQ& ins)
    {
        using ARGS = typename remove_first_type<REQ>::type;
        using func_type = RET (*)(ARGS);
        // XXX cache the function pointer
        auto func = (func_type)dlsym(handle_, std::get<0>(ins).c_str());
        if (!func) {
            std::cerr << "failed to lookup func" << std::endl;
            exit(3);
        }
        return func(pop_front(ins));
    }

private:
    void* handle_;
};

template<std::size_t SZ = 4096,
         typename SERV = std::void_t<void>>
class Proxy {
public:

    template<typename... Args>
    static
    decltype(auto)
    Build(Args... args) {
        if constexpr (sizeof...(args) == 0) {
            return ProxyDirect<SZ, SERV>{};
        } else if constexpr (sizeof...(args) == 1) {
            return ProxySO<SZ>{args...};
        }
    }

};
