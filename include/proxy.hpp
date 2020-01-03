#pragma once

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <atomic>
#include <cstdint>
#include <iostream>
#include <memory>
#include <type_traits>
#include <exception>
#include <unordered_set>
#include <unordered_map>
#include <thread>
#include <random>
#include <functional>

#include <dlfcn.h>
#include <immintrin.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>


#define PROXY_LOG(c) PROXY_LOG_##c
#define PROXY_LOG_ERR std::cerr
#define PROXY_LOG_DBG std::cerr
#define PROXY_LOG_INF std::cerr


namespace capsiproxy {


class ParentTerminated:                         public std::exception {};
class ChildTerminated:                          public std::exception {};
class HangUpRequest:                            public std::exception {};
class OperationFailed:                          public std::exception {};
class ExtractionBufferOverflow:                 public std::exception {};
class SendBufferOverflow:                       public std::exception {};
class SignalHandlerInstalltionFailure:          public std::exception {};
class ChildReadCommandSocketFailed:             public std::exception {};
class ParentWrite2CommandSocketFailed:          public std::exception {};
class TriedToStopNonExistentSegmentDescriptor:  public std::exception {};
class OpeningDSOFailed:                         public std::exception {};
class DSOFunctionLookupFailed:                  public std::exception {};
class InvalidProxyState:                        public std::exception {};

namespace detail {

inline bool parent_terminated_check();
inline void* open_map_shm(char const* name, std::size_t sz, bool auto_unlink);

class NullBuffer : public std::streambuf
{
public:
    int overflow(int c) { return c; }
};

class NullStream : public std::ostream
{
public:
    NullStream()
        : std::ostream(&m_sb_) {}
private:
    NullBuffer m_sb_;
} null_stream;

enum ChannelStatus {
    kOpen,
    kClosed,
};

enum ChannelSide {
    kParent,
    kChild,
};

constexpr uint32_t     kSegmentMagic = 0xc7390fbc;
constexpr std::size_t  kSHMAlignment = 8;
constexpr std::size_t  kPageSize     = 4098;

/**
 * Round up x to the smallest multiple of y.
 * @param  x: The value to be rounded up
 * @param  y: The multiplier
 * @retval Returns the smallest integral value that is greater than or equal to
 * x, and is a multiple of y
 */
inline std::size_t
div_round_up(int x, int y)
{
    return y * (1 + (x - 1) / y);
}

/**
 * Given a tuple, this function creates and returns a tuple contain all but its
 * first element.
 */
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

/**
 * Auxiliary function to open a shared memory segment and map it into the address
 * space of the current process.
 * @param  name: The name of the named shared memory.
 * @param  sz: The size of the shared memory segment.
 * @param  auto_unlink: If true, this function unlinks the named shared memory
 * after mapping it.
 * @retval Upon success this function returns a void* pointer to the beginning
 * of the shared memory segment.
 */
void*
open_map_shm(char const* name, std::size_t sz, bool auto_unlink)
{
    int fd = shm_open(name, O_RDWR | O_CREAT, S_IRWXU);
    if (fd == -1) {
        PROXY_LOG(ERR) << "Cannot create shared memory for segment";
        PROXY_LOG(ERR) << "shm_open: " << strerror(errno) << std::endl;
        exit(98);
    }
    int ret = ftruncate(fd, sz);
    if (ret == -1) {
        PROXY_LOG(ERR) << "Cannot ftruncate shared memory for segment";
        exit(99);
    }
    void* m = mmap(nullptr, sz,
                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) {
        PROXY_LOG(ERR) << "Cannot map shared memory for segment";
        exit(100);
    }
    if (auto_unlink) {
        ret = shm_unlink(name);
        if (ret) {
            PROXY_LOG(ERR) << "Cannot unlink the shared memory of segment";
            PROXY_LOG(ERR) << "shm_unlink: " << strerror(errno) << std::endl;
            exit(101);
        }
    }
    return m;
}

template<std::size_t SZ>
class SegmentDescriptor;

/**
 * An instance of Channel, represents a one-way communication medium between the
 * client process and one of its server processes. In other words, for each pair
 * of client/server we need 2 instances of channel.
 * This implementation is based on POSIX named shared memory.
 */
template <std::size_t SZ>
class Channel {
public:
    friend class SegmentDescriptor<SZ>;
    Channel(std::size_t sz, std::string name, bool auto_unlink)
        : size_{sz}, name_{name}
    {
        PROXY_LOG(DBG) << "Creating channel - name: " << name << " size: " << sz << std::endl;
        base_ = open_map_shm(name.c_str(), sz, auto_unlink);
    }

    ~Channel()
    {
        PROXY_LOG(DBG) << "Destructing channel '" << name_ << "'" << std::endl;
        int ret = munmap(base_, size_);
        std::cerr << std::flush;
        if (ret)
            PROXY_LOG(ERR) << "Cannot unmap channel memory '" << name_ << "'" << std::endl;
    }

    operator void* ()
    {
        return base_;
    }

private:
    uint64_t      size_;
    std::string   name_;
    void*         base_;
    ChannelStatus status_;
#ifdef PROXY_DBG
    uint32_t      canary = 0xdeadbeaf;
#endif
};

/**
 * Segment is a wrapper around a Channel that provides higher level operations
 * such is laying out values into the channel memory, and parsing values from it.
 * 
 * @tparam SZ: The size of the shared memory segment used by each channel. SZ should
 * be large enough for the memory segment to be able to accomodate all of the arguments
 * or the return value with correct alignment.
 */
template<std::size_t SZ>
class Segment {
public:
    friend class SegmentDescriptor<SZ>;

    Segment(bool init_turn, std::size_t memsz)
        : autounmap_{this, memsz},
          turn_{init_turn ? kParent : turn_},
          chan_sz_{SZ},
          memsz_{memsz}
    {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
        pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
    }

    __always_inline
    bool ParentTurn() { return turn_ == kParent; }
    __always_inline
    bool ChildTurn() { return !ParentTurn(); }

    template <int N, typename TUP>
    void
    ExtractElem(TUP& instance, void*& recv)
    {
        if constexpr (std::tuple_size<TUP>::value >= N + 1)
        {
            using TYPE = std::tuple_element_t<N, TUP>;
            if constexpr (std::is_same<TYPE, std::string>::value) {
                char* item = static_cast<char*>(recv);
                PROXY_LOG(DBG) << "Extracted string value: " << item << std::endl;
                std::string tmp {item};
                std::get<N>(instance) = tmp;
                recv += tmp.size();
                chan_sz_ -= tmp.size();
                auto ret = std::align(kSHMAlignment, 1, recv, chan_sz_);
                if (ret == nullptr)
                    throw ExtractionBufferOverflow{};
            } else {
                std::add_pointer_t<TYPE> p0;
                auto item = static_cast<decltype(p0)>(recv);
                PROXY_LOG(DBG) << "Extracted non-string value: " << *item << std::endl;
                std::get<N>(instance) = *item;
                recv += sizeof(item);
                chan_sz_ -= sizeof(item);
                auto ret = std::align(kSHMAlignment, 1, recv, chan_sz_);
                if (ret == nullptr)
                    throw ExtractionBufferOverflow{};
            }
        }
    }

    template <typename T>
    auto
    ExtractParams(void* recv)
    {
        PROXY_LOG(DBG) << "ExtractParams: " << recv << std::endl;
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

    std::size_t
    GetSize()
    {
        return memsz_;
    }
    
    bool
    HangUpRequested() { return status_ == kRequestHangUp; }

    ~Segment() {
        status_ = kRequestHangUp;
        PROXY_LOG(DBG) << "Destructing segment";
    }

private:
    class AutoUnmapper {
    public:
        AutoUnmapper(void* ptr, std::size_t sz)
            : ptr_{ptr}, sz_{sz} {}
        ~AutoUnmapper()
        {
            PROXY_LOG(DBG) << "unmap segment memory";
            int ret = munmap(ptr_, sz_);
            if (ret)
                PROXY_LOG(DBG) << "Cannot unmap channel memory: " << strerror(errno);
        }
    private:
        void* ptr_;
        std::size_t sz_;
    };
    enum SegmentStatus {
        kActive,
        kRequestHangUp,
    };

    // XXX: use a ring queue so that we can have multiple requests queued at the same time.
    AutoUnmapper autounmap_;
    volatile ChannelSide turn_;
    uint32_t             magic_ = kSegmentMagic;
    std::size_t          chan_sz_;
    SegmentStatus volatile status_{kActive};
    std::size_t memsz_;
};

template<std::size_t SZ>
class SegmentDescriptor {
public:
    template <typename... Args>
    void
    SendRequest(Args... args)
    {
        Unroll(GetSendChannel(), SZ, args...);
        Switch();
    }

    template <typename T, typename... Args>
    void
    Unroll(void* base, std::size_t chan_sz, T t, Args... args)
    {
        PROXY_LOG(DBG) << "Unroll: " << base << "  <-- " << t << std::endl;
        if constexpr (std::is_same<T, std::string>::value) {
            char* base_param = static_cast<char*>(base);
            strcpy(base_param, t.c_str());
            std::string::size_type strlen = t.size();
            base += strlen;
            chan_sz -= strlen;
            auto ret = std::align(kSHMAlignment, 1, base, chan_sz);
            if (ret == nullptr)
                throw SendBufferOverflow{};
        } else {
            T* base_param = static_cast<T*>(base);
            *base_param = t;
            base += sizeof(T);
            chan_sz -= sizeof(T);
            auto ret = std::align(kSHMAlignment, 1, base, chan_sz);
            if (ret == nullptr)
                throw SendBufferOverflow{};
        }

        if constexpr (sizeof...(args) > 0)
            Unroll(base, chan_sz, args...);
    }

    template <typename T>
    auto
    ExtractParams()
    {
        PROXY_LOG(DBG) << ((side_ == kParent) ? "Parent" : "Child")
                       << " is waiting for its turn" << std::endl;
        Wait(child_pid_);
        if (side_ == kChild && segment_.HangUpRequested()) {
            PROXY_LOG(DBG) << "Child: Got HangUp request1" << std::endl;
            throw HangUpRequest{};
        }
        PROXY_LOG(DBG) << ((side_ == kParent) ? "Parent" : "Child")
                       << " is going to extract" << std::endl;
        return segment_.template ExtractParams<T>(GetRecvChannel());
    }

    template <typename T>
    void
    PutResult(T& tup)
    {
        segment_.template PutResult<T>(tup);
        Switch();
    }

    Channel<SZ>& GetSendChannel()
    {
        return ((side_ == kParent) ? send_ : recv_);
    }

    Channel<SZ>& GetRecvChannel()
    {
        return ((side_ == kParent) ? recv_ : send_);
    }

    SegmentDescriptor(std::string name, ChannelSide side, Segment<SZ>& seg, pid_t cp)
        : side_{side},
          segment_{seg},
          child_pid_{cp},
        /**
         * The named shared memory was used to establish a communication channel
         * the client and server processes. After the channel is connected, we
         * no longer need keep the named shared memory linked in /dev/shm.
         * We do the unlinking on the child (server) side after opening the channels.
         */
          send_{SZ, name + "_ch_c2s", /*auto unlink*/ side == kChild},
          recv_{SZ, name + "_ch_s2c", /*auto unlink*/ side == kChild}
    {

        GetSendChannel().status_ = kOpen;
    }

    ~SegmentDescriptor()
    {
        GetSendChannel().status_ = kClosed;
        Switch();
        segment_.~Segment();
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
                PROXY_LOG(ERR) << "Failed: Cannot make the mutex consistent!";
            else
                PROXY_LOG(ERR) << "Mutex recovered";
        } else if (rc == ENOTRECOVERABLE) {
                PROXY_LOG(ERR) << "Failed: Another process has failed to recover " \
                                    "the mutex and mark it consistent.";
        } else if (rc) {
                PROXY_LOG(ERR) << "Failed.";
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
            PROXY_LOG(ERR) << "Cannot unlock mutex: EPERM";
            exit(1);
        } else if (rc == EINVAL) {
            PROXY_LOG(ERR) << "Cannot unlock mutex: EINVAL";
            exit(1);
        }
    }


    bool VerifyIntegrity() const
    {
        return segment_.magic_ == kSegmentMagic;
    }

    bool
    ChildTerminatedCheck(pid_t cp)
    {
        int status;
        int ret = waitpid(cp, &status, WNOHANG);
        if (ret > 0 && (WIFEXITED(status) || WIFSIGNALED(status) || WIFSTOPPED(status)))
            return true;
        return false;
    }

    void Wait(pid_t cp)
    {
        if (side_ == kParent) {
            while(segment_.turn_ == kChild) {
                _mm_pause();
                usleep(1);
                if (ChildTerminatedCheck(cp)) {
                    segment_.turn_ = kParent;
                    throw ChildTerminated{};
                }
            }
        } else if (side_ == kChild) {
            while(segment_.turn_ == kParent) {
                _mm_pause();
                usleep(1);
                if (parent_terminated_check()) {
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

    bool
    HangUpRequested()
    {
        return segment_.HangUpRequested();
    }

private:
    ChannelSide     side_;
    Segment<SZ>&    segment_;
    pid_t           child_pid_;
    Channel<SZ>     send_;
    Channel<SZ>     recv_;
};


inline
bool parent_terminated_check()
{
    return getppid() == 1;
}


template<std::size_t SZ>
class Stub {
public:
    Stub(SegmentDescriptor<SZ>& segd)
        : chan_sz_{SZ},
          segd_{segd}
    { }

    template <typename... Args>
    void
    SendRequest(Args... args)
    {
        segd_.SendRequest(args...);
    }

    template <typename R>
    auto
    ExtractParams()
    {
        auto rt = segd_.template ExtractParams<std::tuple<R>>();
        R r = std::get<0>(rt);
        return r;
    }

private:
    std::size_t chan_sz_;
    SegmentDescriptor<SZ>& segd_;
};

extern "C"
void sig_livecheck_handler(int signo);

extern "C"
void
sig_livecheck_handler(int signo)
{
    if (parent_terminated_check())
    {
        PROXY_LOG(INF) << "Child: parent terminated.";
        exit(0);
    }
}

template<typename T>
struct remove_first_type
{};

template<typename T, typename... Ts>
struct remove_first_type<std::tuple<T, Ts...>>
{
    using type = std::tuple<Ts...>;
};

/**
 * The base type for all proxy instances. This base class contains functions and
 * members that are not dependent on any template parameters.
 */
class BaseProxy {
protected:
    constexpr static std::size_t kSegNameSizeMax = 32;
    /**
     * These are the command codes that the client (parent) process may send to
     * server (chidl) process.
     */
    enum CommandCode {
        // Start a new channel and thread for this service type.
        kNewChannel,
        // Stop only this specific service type.
        kHangUp,
        // Stop this child process completely.
        kShutDownRequest,
    };
    /**
     * The structure that represents a specific command and its parameters from
     * the client process to the server. Instances of this struct are passed over
     * the management socket from client to server.
     */

    __attribute__((packed))
    struct Command {
        char seg_name[kSegNameSizeMax];
        // The function that the service thread should execute
        void* service_func;
        CommandCode code;
    };

    /**
     * This set is shared among all instances of proxy types
     * for all child processes and all services. This is ensure
     * That the same named shared memory object is not used twice.
     */
    static std::unordered_set<std::string> shared_mem_names;

    std::string
    GenerateShMemName()
    {
        static char kProxyPrefix[] = "/";
        static char kProxySuffix[] = "_proxy";
        std::size_t randlen = kSegNameSizeMax -
                              sizeof(kProxySuffix) -
                              sizeof(kProxyPrefix) - 1;
        while(true) {
            auto s = GenerateRandomString(randlen);
            if (shared_mem_names.find(s) == shared_mem_names.end()) {
                shared_mem_names.insert(s);
                return std::string{kProxyPrefix} + s + std::string{kProxySuffix};
            }
        }
    }

    std::string
    GenerateRandomString(std::string::size_type length)
    {
        static auto& chrs = "0123456789"
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        thread_local static std::mt19937 rg{std::random_device{}()};
        thread_local static std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);
        std::string s;
        s.reserve(length);
        while(length--)
            s += chrs[pick(rg)];
        return s;
    }
};

std::unordered_set<std::string> BaseProxy::shared_mem_names{};

/**
 * This function wrapper wraps the appropriate type of STartServiceLoop
 * member function instance inside a plain function. We need this to be
 * able to get a regular function pointer to represent the service loop,
 * because a function member pointer cannot be portably and reliably
 * passed between process instances.
 * 
 * @param  proxy: The instance of the proxy object owning the specific
 * service loop we want to pass to the child process.
 * 
 * @param  segd: The segment descriptor corresponding to the specific
 * child process and function type.
 */
template<typename Proxy, std::size_t SZX, typename RET, typename... Args>
void
AbstractProxyWorkLoopWrapper(Proxy proxy, SegmentDescriptor<SZX>* segd)
{
    proxy->template StartServiceLoop<RET, Args...>(segd);
}

template <typename SUB, std::size_t SZ>
class AbstractProxy: public BaseProxy {
public:
    /**
     * This function implements the service loop for each worker thread in the
     * child (server). For each channel there is exactly one thread that runs
     * this service loop with the types Args and RET appropriate for its corresponding
     * fucntion.
     * 
     * @tparam RET: The return type of the service function.
     * 
     * @tparam Args: The argument types of service function.
     * 
     * @param segd: A pointer to the appripriate segment descriptor.
     */
    template<typename RET, typename... Args>
    void
    StartServiceLoop(SegmentDescriptor<SZ>* segd)
    {
        PROXY_LOG(DBG) << "Starting Service Loop." << std::endl;
        while (true) {
            try {
                auto ins = segd->template ExtractParams<std::tuple<Args...>>();
                RET result = static_cast<SUB*>(this)->template Do<RET>(ins);
                PROXY_LOG(DBG) << "Child: Result ready: " << result << std::endl;
                // Send the result back to the parent process.
                segd->SendRequest(result);
            } catch (ParentTerminated& pte) {
                PROXY_LOG(INF) << "Child: Parent terminated" << std::endl;
                exit(0);
            } catch (HangUpRequest& hure) {
                PROXY_LOG(INF) << "Child: Got hangup request2" << std::endl;
                /**
                 * Free the segment and channel resources and return from this
                 * function to terminate this service this.
                 */
                segd->~SegmentDescriptor();
                return;
            }
        }
        __builtin_unreachable();
    }

    /**
     * This makes the child (server) get stuck in the service loop and wait for
     * requests from the parent (client). When the parent calls this function, it
     * just returns without blocking.
     */
    void
    BlockChildOnCommandLoop()
    {
        if (side_ == kChild)
            CommandServerLoop();
    }

    /**
     * Instruct the child (server) corresponding to this instance of AbstractProxy
     * to shutdown and exit. This will stop all services provided by this instance
     * of server.
     */
    void
    ShutdownServer()
    {
        Command cmd;
        cmd.code = kShutDownRequest;
        PROXY_LOG(DBG) << "Going to send Shutdown request to child" << std::endl;
        int ret = write(GetCommandSocket(), &cmd, sizeof(cmd));
        if (ret == -1) {
            PROXY_LOG(ERR) << "Cannot write kShutdown request";
            exit(77);
        }
    }

protected:

    /**
     * Inform the server (child) process that it should open a new communication
     * channel to serve a new type of function type.
     * 
     * @tparam SFUNC: The type of the service function to be sent to the server
     * process.
     * 
     * @param  name: Name of the communication channel. The client uses this name
     * to generate the names of the shared memory segments it has to map in its
     * address space.
     * 
     * @param  service_func: The function pointer to the function the server should
     * use to carry out the requested operations.
     */
    template<typename SFUNC>
    void
    SendNewChannelInfo(std::string name, SFUNC service_func)
    {
        Command cmd;
        assert(name.size() < sizeof(cmd.seg_name));
        strcpy(cmd.seg_name, name.c_str());
        cmd.service_func = reinterpret_cast<void*>(service_func);
        cmd.code = kNewChannel;
        int ret = write(GetCommandSocket(), &cmd, sizeof(cmd));
        if (ret == -1)
            PROXY_LOG(ERR) << "Cannot write kNewChannel request";
    }

    /**
     * Setup communication channels between a child and server process for a specific
     * type of function.
     * 
     * @param  name: Name of the segment descriptor which can be used to generate
     * the names of the shared memory segments that hold the segment and its related
     * cahnnels.
     * 
     * @param  side: Indicates which side of the channel we are supposed to be. This
     * is relevant, because the parent (client) is responsible for initializing the
     * data structures residing in these shared memory areas.
     * 
     * @retval Returns the newly created segment descriptor.
     */
    SegmentDescriptor<SZ>*
    OpenChannel(std::string name, ChannelSide side)
    {
        /**
         * On the child side just unlink the named shared memory, since it is
         * not needed any more. The parent (client) must have already opened and
         * mapped it into its address space.
         */
        bool auto_unlink_shm {side == kChild};
        /**
         * Calculate the minumum possible size for the shared memory segment.
         */
        std::size_t seg_memsz = div_round_up(sizeof(Segment<SZ>), kPageSize);

        void* m = open_map_shm(name.c_str(), seg_memsz, auto_unlink_shm);
        Segment<SZ>* seg = new (m) Segment<SZ>{side == kParent, seg_memsz};
        auto segd = new SegmentDescriptor<SZ>(name, side, *seg, child_pid_);
        return segd;
    }

    /**
     * The main loop of the child (server) process to receive and take action
     * on management commands from the parent (client) process.
     */
    void
    CommandServerLoop()
    {
        PROXY_LOG(DBG) << "Starting command loop for child." << std::endl;
        while (true) {
            auto cmd = WaitForCommand();
            switch (cmd->code)
            {
            /**
             * This command shows that a function of a specific type has been
             * invoked in the client for the first time. Thus the child process
             * should create the related channels and thread to be able to
             * handle requests of this type.
             */
            case kNewChannel:
                PROXY_LOG(DBG) << "Child: Got command: kNewChannel - segname: " << cmd->seg_name << std::endl;
                // Extract the service function from the Command object
                using WT = void(*)(decltype(this), SegmentDescriptor<SZ>*);
                WT service_func;
                service_func = reinterpret_cast<WT>(cmd->service_func);
                // Extract the name of the segment descriptor from the Command
                // object and open it.
                SegmentDescriptor<SZ>* segd;
                segd = OpenChannel(cmd->seg_name, kChild);
                // Start a service thread
                std::thread* thr;
                thr = new std::thread{service_func, this, segd};
                threads_.insert({segd, thr});
                thr->detach();
                break;

            /**
             * The client (parent) has requested to close the cnannels and stop
             * the thread responsible for handing requests of a specific type.
             */
            case kHangUp:
                PROXY_LOG(DBG) << "Child: Got command: kHangUp" << std::endl;
                break;

            /**
             * The client (parent) has requested to shutdown/exit this child
             * (server) process completely.
             */
            case kShutDownRequest:
                PROXY_LOG(DBG) << "Child: Got command: kShutDown" << std::endl;
                exit(0);
                break;
            }
        }
        PROXY_LOG(INF) << "Child command loop terminated." << std::endl;
        exit(23);
    }

    /**
     * Send a management command to the child (server) process.
     * @param cmd: The command to be sent to the server.
     */
    void
    SendCommand(Command const& cmd) const
    {
retry_send_command:
        int ret = write(GetCommandSocket(), reinterpret_cast<void const*>(&cmd), sizeof(cmd));
        if (ret == -1) {
            if (errno == EINTR || errno == EWOULDBLOCK) {
                goto retry_send_command;
            } else {
                throw ParentWrite2CommandSocketFailed{};
            }
        }
    }

    /**
     * The child (server) process call this method to block and wait for management
     * commands from the parent (client) process.
     */
    std::shared_ptr<Command>
    WaitForCommand() const
    {
        Command* cmd = new Command{};
retry_read_command:
        int ret = read(GetCommandSocket(), static_cast<void*>(cmd), sizeof(Command));
        if (ret == -1) {
            if (errno == EINTR || errno == EWOULDBLOCK) {
                /**
                 * EINTR might be a result of the periodic SIGALRM we send to self
                 * allow the server process to wake up for housekeeping purposes.
                 */
                goto retry_read_command;
            } else {
                throw ChildReadCommandSocketFailed{};
            }
        }
        return std::shared_ptr<Command>(cmd);
    }

    int
    GetCommandSocket() const
    {
        return (side_ == kParent) ? cmd_ch_[0] : cmd_ch_[1];
    }

    AbstractProxy()
    {
        CreateManagementSockets();
        StartServer();
        status_ = kProxyActive;
    }

    /**
     * Create a pair of Unix domain datagram sockets that are used for managing
     * the server process.
     */
    void
    CreateManagementSockets()
    {
        int ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, cmd_ch_);
        if (ret) {
            PROXY_LOG(ERR) << "cannot create socket pair" << std::endl;
            PROXY_LOG(ERR) << "socketpair: " << strerror(errno) << std::endl;
            exit(44);
        }
    }

    /**
     * Fork the server process, and set some related variables.
     */
    void
    StartServer()
    {
        PROXY_LOG(DBG) << "About to fork()";
        pid_t pid = fork();
        if (pid == 0) {
            // Child (Server)
            side_ = kChild;
            ActivateLiveCheck();
        } else if (pid > 0) {
            // Parent (Client)
            side_ = kParent;
            child_pid_ = pid;
        } else {
            PROXY_LOG(ERR) << "fork() failed: ";
            exit(33);
        }
    }

    /**
     * The main thread in the server process, blocks on the communication socket
     * that is used to convey management requests from the client process. This
     * may cause the server to miss certain events/changes that may occur in its
     * operation environment. We use a signal to interrupt the 'read' syscall on
     * this socket, so that the server gets a chance to check certain parameters
     * and restart the syscall if necessary.
     */
    void
    ActivateLiveCheck()
    {
        InstallLiveCheckSignalHandlers();
        StartLiveCheckSignalTimer();
    }

    /**
     * Create a POSIX timer to send a SIGALRM regularly.
     */
    void
    StartLiveCheckSignalTimer()
    {
        struct itimerval val;
        val.it_value.tv_sec = 1;
        val.it_value.tv_usec = 0;
        val.it_interval = val.it_value;
        int ret = setitimer(ITIMER_REAL, &val, NULL);
        if (ret)
            PROXY_LOG(ERR) << "setitimer: " << strerror(errno);
    }

    /**
     * Install signal handler for SIGALRM. See comments above on method
     * 'ActivateLiveCheck()'.
     */
    void
    InstallLiveCheckSignalHandlers()
    {
        struct sigaction sa;
        sa.sa_handler = sig_livecheck_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        if (sigaction(SIGALRM, &sa, nullptr) < 0)
            throw SignalHandlerInstalltionFailure{};
    }

public:
    class AbstractExecution {};

    /**
     * @tparam PRX The type of the Porxy object that holds this Execution
     * instance.
     * @tparam RET The type of the result of the operation.
     * @tparam Args The types of the arguments to be supplied to the
     * operation.
     */
    template <typename PRX, typename RET, typename... Args>
    class Execution: public AbstractExecution {
    public:
        Execution(PRX* proxy)
            : proxy_{proxy}
        {}

        /**
         * The main method of the class Execution that establishes the channel
         * on first call, and then uses that channel (stub) to send requests
         * to the child (server) process, and retreive the result.
         * @param  args: The arguments to pass to the function in the server
         * process.
         * @retval Returns the result of the operations as performed by the
         * server process.
         */
        RET
        _(Args... args)
        {
            if (!segd_) {
                PROXY_LOG(DBG) << "+ Creating new segment descriptor." << std::endl;
                auto shmnam = proxy_->GenerateShMemName();
                PROXY_LOG(DBG) << "+ New segment descriptor name: " << shmnam << std::endl;
                segd_ = proxy_->OpenChannel(shmnam, kParent);
                stub_ = new Stub<SZ>(*segd_);
                auto service_func =
                    &AbstractProxyWorkLoopWrapper<decltype(proxy_), SZ, RET, Args...>;
                proxy_->SendNewChannelInfo(shmnam, service_func);
            } else {
                PROXY_LOG(DBG) << "Reusing existing segment descriptor." << std::endl;
            }
            stub_->SendRequest(args...);
            RET result = stub_->template ExtractParams<RET>();
            return result;
        }

        /**
         * Completely shutdown the child (server) process attached to this
         * Execution instance. 
         */
        void
        Shutdown()
        {
            proxy_->ShutdownServer();
        }

        /**
         * This Execution instance represents that Segment and channels
         * and the thread that is responsible for serving requests of
         * the specific types. Destruction of this Execution instance
         * should normally be accompanied by closing those segments and
         * channels.
         */
        ~Execution()
        {
            delete segd_;
            delete stub_;
        }

    private:
        /**
         * The Proxy that owns this Execution instance
         */
        PRX* proxy_;
        /**
         * The segment descriptor that is used to work with the relevant
         * segment and channels.
         */
        SegmentDescriptor<SZ>* segd_{nullptr};
        /**
         * A Stub instance is used to carry out Send/Receive operations
         * using the server process. This is the representative of the
         * server process on the client side.
         */
        Stub<SZ>* stub_{nullptr};
        /**
         * The PID of the child (server) process that this Execution
         * instance uses.
         */
        pid_t child_pid_;
    };

    /**
     * This enumeration is used for selecting the operation to be executed
     * by ExecuteInternal. All of these types are handled by the same
     * function, because they all need the same local static variables.
     */
    enum Selector {
        // Send arguments and retrieve the result.
        kQuery,
        // Stop the thread/channels for this specific function type.
        kStop,
        // Stop the child (server) process.
        kShutDown,
    };

    template <typename RET, typename... Args>
    RET
    ExecuteInternal(Selector sel, Args... args)
    {
        static std::unordered_map<decltype(this), Execution<AbstractProxy<SUB, SZ>, RET, Args...>*> executions{};
        Execution<AbstractProxy<SUB, SZ>, RET, Args...>* execution = nullptr;
        auto iter = executions.find(this);
        if (iter == executions.end()) {
            if (sel == kQuery) {
                execution = new Execution<AbstractProxy<SUB, SZ>, RET, Args...>{this};
                executions.insert({this, execution});
            } else
                throw TriedToStopNonExistentSegmentDescriptor{};
        } else {
            execution = std::get<1>(*iter);
            if (sel == kStop) {
                PROXY_LOG(DBG) << "Parent: Got kStop command for Execution instance";
                executions.erase(iter);
                PROXY_LOG(DBG) << "executions count: " << executions.size() << std::endl;
                delete execution;
                return RET{};
            } else if (sel == kShutDown) {
                PROXY_LOG(DBG) << "Parent: Got kShutDown command for Execution instance";
                executions.erase(iter);
                execution->Shutdown();
                for (auto& e : executions)
                    delete std::get<1>(e);
                executions.clear();
                return RET{};
            }
        }
        if (sel == kQuery)
            return execution->_(args...);
    }

    /**
     * Send the arguments to the child (server) process and get
     * the result. The relevant server / thread / segment is
     * automatically determined by the types of arguments and
     * the return type.
     * @param  args: 
     * @retval Returns the result of the operation as returned by by
     * the child (server) process.
     */
    template <typename RET, typename... Args>
    RET
    Execute(Args... args)
    {
        if (status_ != kProxyActive)
            throw InvalidProxyState{};
        return ExecuteInternal<RET, Args...>(kQuery, args...);
    }

    /**
     * Stop the thread responsible for serving this service function
     * type and close its segment descriptor and channels.
     * @param  args: These args are only needed to give access to the
     * relevant `executions` static variable in ExecuteInternal.
     * @retval Return value should not be used.
     */
    template <typename RET, typename... Args>
    RET
    Stop(Args... args)
    {
        if (status_ != kProxyActive)
            throw InvalidProxyState{};
        ExecuteInternal<RET, Args...>(kStop, args...);
        return RET{};
    }

    /**
     * Stop the server (child) process responsible for carrying out
     * the requests to this proxy instance.
     * @param  args: These args are only needed to give access to the
     * relevant `executions` static variable in ExecuteInternal.
     * @retval Return value should not be used.
     */
    template <typename RET, typename... Args>
    RET
    Shutdown(Args... args) {
        if (status_ != kProxyActive)
            throw InvalidProxyState{};
        status_ = kProxyShutDown;
        ExecuteInternal<RET, Args...>(kShutDown, args...);
        return RET{};
    }

protected:
    /**
     * Indicates wether this instance is running in the client (parent)
     * or child (server) side.
     */
    ChannelSide side_;
    /**
     * On the client (parent) side, this member of proxy holds the PID
     * of the server (child) process.
     */
    pid_t child_pid_;
    /**
     * Unix domain datagram sockets that are used by the client (parent)
     * process to control the child (server) process. These sockets
     * are NOT used for data transfer, but only for management of the
     * processes.
     * Channel 0: Parent --> Child
     * Channel 1: Child  --> Parent
     */
    int cmd_ch_[2];

    enum PorxyStatus {
        kProxyShutDown,
        kProxyActive,
        kProxyInit,
    } status_ {kProxyInit};


private:
    /**
     * A mapping from Segmen Descriptors to the threads responsible for
     * handling the requests on that segment.
     */
    std::unordered_map<SegmentDescriptor<SZ>*, std::thread*> threads_;
};

} // End of namespace 'detail'

/**
 * @brief  ProxyDirect runs a child process that can serve the request of its
 * clients using class SERV.
 * 
 * @tparam SZ the size of the shared memory region.
 */
template <std::size_t SZ, typename SERV>
class ProxyDirect final: public detail::AbstractProxy<ProxyDirect<SZ, SERV>, SZ> {
public:
    ProxyDirect()
        : detail::AbstractProxy<ProxyDirect, SZ>{},
          service_{}
    {}

    /**
     * @brief  This method assumes that class SERV has a method Handle()
     * that takes a parameter of type REQ. REQ must be an instance of
     * std::tuple<> with appropriate types.
     * @retval Returns a value of type RET which is returned by the
     * corresponding Handle() method in SERV.
     */
    template<typename RET, typename REQ>
    RET
    Do(REQ& ins)
    {
        return service_.Handle(ins);
    }

private:
    SERV service_;
};

/**
 * @brief  ProxySO runs a child process that can serve the request of its
 * clients using the supplied DSO file.
 * 
 * @tparam SZ the size of the shared memory region.
 */
template <std::size_t SZ>
class ProxySO final: public detail::AbstractProxy<ProxySO<SZ>, SZ> {
public:
    ProxySO(std::string soname)
        : detail::AbstractProxy<ProxySO, SZ>{}
    {
        using namespace detail;
        PROXY_LOG(DBG) << "Going to dlopen '" << soname << "'" << std::endl;
        handle_ = dlopen(soname.c_str(), RTLD_LOCAL | RTLD_NOW);
        if (!handle_) {
            PROXY_LOG(ERR) << "Failed to open DSO!" << std::endl;
            throw OpeningDSOFailed{};
        }
    }

    /**
     * @brief  This method assumes that the DSO a method whose name is
     * the first element of the ins tuple. This method takes parameters
     * of type REQ. REQ must be an instance of std::tuple<> with appropriate
     * types.
     * 
     * @retval Returns a value of type RET which is returned by the
     * corresponding method in the DSO.
     */
    template<typename RET, typename REQ>
    RET
    Do(REQ& ins)
    {
        using namespace detail;
        using ARGS = typename remove_first_type<REQ>::type;
        using func_type = RET (*)(ARGS);
        auto func_name = std::get<0>(ins);
        func_type func_ptr;
        auto func_iter = funcs_.find(func_name);
        if (func_iter == funcs_.end()) {
            /* Function is not in cache (i.e not already looked up). */
            PROXY_LOG(DBG) << "DSO function cache miss: (" << func_name.c_str() << ")" << std::endl;
            func_ptr = (func_type)dlsym(handle_, func_name.c_str());
            funcs_[func_name] = (void*)func_ptr;
            if (!func_ptr) {
                PROXY_LOG(ERR) << "Failed to lookup function in DSO" << std::endl;
                PROXY_LOG(ERR) << "dlerror: " << dlerror() << std::endl;
                throw DSOFunctionLookupFailed{};
            }
        } else {
            PROXY_LOG(DBG) << "DSO function cache hit: (" << func_name.c_str() << ")" << std::endl;
            func_ptr = reinterpret_cast<func_type>(std::get<1>(*(func_iter)));
        }
        /**
         * Remove the first element of tuple ins, (which is the name of
         * the function), and pass the rest as arguments to the function.
         */
        auto func_args = pop_front(ins);
        RET result = func_ptr(func_args);
        return result;
    }

private:
    /**
     * The handle to the DSO opened via the DLOpen API.
     */
    void* handle_;
    /**
     * A cache of the handles to the functions looked up in the DSO.
     */
    std::unordered_map<std::string, void*> funcs_;
};

/**
 * @brief  Convenience class for using ProxyDirect and ProxySO classes.
 * 
 * @tparam SZ Size of shared memory region for passing arguments and 
 * return values, back and forth between the client and server processes.
 * SZ should be large enough to contain all arguments taking into account
 * the paddings necessery for fix the alignments of values.
 * 
 * @tparam SERV The class that implements the operation that should be
 * executed securely by the server process. If SERV is supplied, then
 * a proxy of type ProxyDirect will be instantiated. Otherwise, ProxySO
 * will be used, since its login is supplied via a DSO.
 * 
 * One reason I use the factory pattern here is that I want to block the
 * child. Had I used the constructors of these classes directly, I would
 * have had to block the child in its constructor, which may be problematic.
 */
template<std::size_t SZ = 4096,
         typename SERV = std::void_t<void>>
class Proxy {
public:

    /**
     * @brief  The Build() overload with no arguments creates a ProxyDirect
     * object that executes request via the SERV class.
     * 
     * @retval Returns an instance of ProxyDirect<SZ, SERV> to the client.
     * In the child (server) instance, this method does not return, but blocks
     * in a service loop that receives request from the parent (client) instance
     * and returns the response.
     */
    static ProxyDirect<SZ, SERV>
    Build()
    {
        auto proxy = ProxyDirect<SZ, SERV>{};
        proxy.BlockChildOnCommandLoop();
        return proxy;
    }

    /**
     * @brief  The Build(std::string) overload creates a ProxySO object
     * that executes request via the DSO with path dso_path.
     * 
     * @retval Returns an instance of ProxySO<SZ> to the client.
     * In the child (server) instance, this method does not return, but blocks
     * in a service loop that receives request from the parent (client) instance
     * and returns the response.
     */
    static ProxySO<SZ>
    Build(std::string dso_path)
    {
        auto proxy = ProxySO<SZ>{dso_path};
        proxy.BlockChildOnCommandLoop();
        return proxy;
    }

};

}
