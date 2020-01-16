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
#include <cstddef>
#include <iostream>
#include <memory>
#include <type_traits>
#include <exception>
#include <unordered_set>
#include <unordered_map>
#include <thread>
#include <random>
#include <iterator>
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
class BadSegment:                               public std::exception {};

namespace detail {

enum ExitCodes {
    EC_OK                               = 0,
    EC_SHM_SEG_CREATE                   = 10,
    EC_SHM_SEG_TRUNCATE                 = 20,
    EC_SHM_SEG_MAP                      = 30,
    EC_SHM_SEG_UNLINK                   = 40,
    EC_SIGNAL_LIVECHECL_INSTALLATION    = 50,
    EC_MAN_SOCK_WRITE_SHUTDOWN          = 60,
    EC_CHILD_LOOP_TERMINATED            = 70,
    EC_SOCKETPAIR_CREATION              = 80,
    EC_FORK_FAILED                      = 90,
};

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
 * The utils namespace holds a bunch of utility stand-alone functions used internally
 * by the implemenation.
 */
inline namespace utils {
inline bool has_parent_terminated();
std::tuple<void*, int> open_map_shm(std::size_t sz);
void* open_map_shm(int fd, std::size_t sz);

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
 * Determines if the parent process of the current process has terminated.
 */
inline
bool has_parent_terminated()
{
    /** If our parent is the init process (PID 1), then our parent has already
     *  exited.
     */
     return getppid() == 1;
}

extern "C"
void
sig_livecheck_handler(int signo)
{
    if (has_parent_terminated())
    {
        PROXY_LOG(INF) << "Child: parent terminated.";
        exit(EC_SIGNAL_LIVECHECL_INSTALLATION);
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

std::string
GenerateShMemName()
{
    constexpr static std::size_t kSegNameSizeMax = 32;
    /**
     * This set is shared among all instances of proxy types
     * for all child processes and all services. This is ensure
     * That the same named shared memory object is not used twice.
     */
    static std::unordered_set<std::string> shared_mem_names;

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
open_map_shm(int fd, std::size_t sz)
{
    int ret = ftruncate(fd, sz);
    if (ret == -1) {
        PROXY_LOG(ERR) << "Cannot ftruncate shared memory for segment";
        exit(EC_SHM_SEG_TRUNCATE);
    }
    void* m = mmap(nullptr, sz,
                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) {
        PROXY_LOG(ERR) << "Cannot map shared memory for segment";
        exit(EC_SHM_SEG_MAP);
    }
    return m;
}

std::tuple<void*, int>
open_map_shm(std::size_t sz)
{
    auto name = detail::GenerateShMemName();
    int fd = shm_open(name.c_str(), O_RDWR | O_CREAT, S_IRWXU);
    if (fd == -1) {
        PROXY_LOG(ERR) << "Cannot create shared memory for segment";
        PROXY_LOG(ERR) << "shm_open: " << strerror(errno) << std::endl;
        exit(EC_SHM_SEG_CREATE);
    }
    auto ptr = open_map_shm(fd, sz);
    int ret = shm_unlink(name.c_str());
    if (ret) {
        PROXY_LOG(ERR) << "Cannot unlink the shared memory of segment";
        PROXY_LOG(ERR) << "shm_unlink: " << strerror(errno) << std::endl;
        exit(EC_SHM_SEG_UNLINK);
    }
    return std::make_tuple(ptr, fd);
}

/**
 * Check if a given child process has exited for any reason.
 * @param  cp: PID of the child process.
 */
bool
has_child_terminated(pid_t cp)
{
    int status;
    int ret = waitpid(cp, &status, WNOHANG);
    if (ret > 0 && (WIFEXITED(status) || WIFSIGNALED(status) || WIFSTOPPED(status)))
        return true;
    return false;
}

/**
 * Calculate the size of the shared memory buffer needed to contain the parameters
 * Args...
 */
template <typename T>
constexpr std::size_t
CalcBufSize()
{
    if constexpr (std::is_same<std::string, T>::value)
        return 8;
    else
        return 8;
}

template <typename T, typename U, typename... Args>
constexpr std::size_t
CalcBufSize()
{
    return CalcBufSize<T>() + CalcBufSize<U, Args...>();
}

} // end of 'utils' namespace

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
    Channel()
    {
        auto [ptr, fd] = open_map_shm(SZ);
        fd_ = fd;
        PROXY_LOG(DBG) << "Created channel fd: " << fd << " size: " << SZ << std::endl;
        base_ = reinterpret_cast<std::byte*>(ptr);
    }

    Channel(int fd)
        : fd_{fd}
    {
        PROXY_LOG(DBG) << "Creating channel - fd: " << fd << " size: " << SZ << std::endl;
        auto ptr = open_map_shm(fd, SZ);
        base_ = reinterpret_cast<std::byte*>(ptr);
    }

    ~Channel()
    {
        if (fd_ < 0)
            return;
        PROXY_LOG(DBG) << "Destructing channel. fd: " << fd_ << std::endl;
        int ret = close(fd_);
        if (ret) {
            PROXY_LOG(ERR) << "Cannot close fd " << fd_ << std::endl;
        }
        ret = munmap(base_, SZ);
        std::cerr << std::flush;
        if (ret)
            PROXY_LOG(ERR) << "Cannot unmap channel memory " << std::endl;
    }

    Channel(Channel const& c) = delete;
    Channel(Channel&& c) = delete;
    Channel& operator=(Channel const& c) = delete;
    Channel& operator=(Channel&& c) = delete;

    std::byte*
    data()
    {
        return base_;
    }

    int
    GetFd() { return fd_; }

private:
    std::byte*    base_;
    ChannelStatus status_;
    int           fd_;
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
        if (!init_turn)
            if (!VerifyIntegrity())
                throw BadSegment{};
    }

    Segment(Segment const& s) = delete;
    Segment(Segment&& s) = delete;
    Segment& operator=(Segment const& s) = delete;
    Segment& operator=(Segment&& s) = delete;

    /**
     * Determines if currently its the client's turn in this channel.
     */
    __always_inline
    bool ParentTurn() { return turn_ == kParent; }
    __always_inline
    bool ChildTurn() { return !ParentTurn(); }

    /**
     * Extract an element of the N-th type in the tuple type TUP from the buffer
     * pointed to by chan_start, and advance chan_start to the next valid data
     * point. The extracted value will be put into the tuple instance.
     * I refrained from returning the extracted value, because we would have had
     * to make an instance (through templatization) of this function for each
     * return type.
     */
    template <int N, typename TUP>
    void
    ExtractElem(TUP& instance, std::byte*& chan_start)
    {
        if constexpr (std::tuple_size<TUP>::value >= N + 1)
        {
            using TYPE = std::tuple_element_t<N, TUP>;
            if constexpr (std::is_same<TYPE, std::string>::value) {
                char* item = reinterpret_cast<char*>(chan_start);
                PROXY_LOG(DBG) << "Extracted string value: " << item << std::endl;
                std::string item_str {item};
                std::string::size_type item_sz = item_str.size();
                std::get<N>(instance) = item_str;
                chan_start += item_sz;
                if (item_sz <= chan_sz_)
                    chan_sz_ -= item_sz;
                else
                    chan_sz_ = 0;
                auto ret = std::align(kSHMAlignment, 1, reinterpret_cast<void*&>(chan_start), chan_sz_);
                if (ret == nullptr)
                    throw ExtractionBufferOverflow{};
            } else {
                std::add_pointer_t<TYPE> p0;
                auto item = reinterpret_cast<decltype(p0)>(chan_start);
                PROXY_LOG(DBG) << "Extracted non-string value: " << *item << std::endl;
                std::get<N>(instance) = *item;
                chan_start += sizeof(item);
                if (sizeof(item) <= chan_sz_)
                    chan_sz_ -= sizeof(item);
                else
                    chan_sz_ = 0;
                auto ret = std::align(kSHMAlignment, 1, reinterpret_cast<void*&>(chan_start), chan_sz_);
                if (ret == nullptr)
                    throw ExtractionBufferOverflow{};
            }
        }
    }

    /**
     * Extract parameters with types as types of tuple T. This method assumes that
     * tuple T has at most 16 elements.
     * 
     * @param  buf: The memory segment in which the raw data is layed out.
     * 
     * @retval Returns a tuple of type T that contains the values extracted
     * from the buffer buf.
     */
    template <typename T>
    auto
    ExtractParams(std::byte* buf)
    {
        PROXY_LOG(DBG) << "ExtractParams: " << buf << std::endl;
        T tup;
        static_assert(std::tuple_size<T>::value <= 17);
        chan_sz_ = SZ;
        ExtractElem<0> (tup, buf);
        ExtractElem<1> (tup, buf);
        ExtractElem<2> (tup, buf);
        ExtractElem<3> (tup, buf);
        ExtractElem<4> (tup, buf);
        ExtractElem<5> (tup, buf);
        ExtractElem<6> (tup, buf);
        ExtractElem<7> (tup, buf);
        ExtractElem<8> (tup, buf);
        ExtractElem<9> (tup, buf);
        ExtractElem<10>(tup, buf);
        ExtractElem<11>(tup, buf);
        ExtractElem<12>(tup, buf);
        ExtractElem<13>(tup, buf);
        ExtractElem<14>(tup, buf);
        ExtractElem<15>(tup, buf);
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
        // Inform the child (server) thread that the channel is closed.
        status_ = kRequestHangUp;
        PROXY_LOG(DBG) << "Destructing segment";
    }

private:
    /**
     * The server process uses this method to verify that the mapped memory for
     * the Segment, contains a valid and already initialized Segment object.
     * @retval Returns true if it detects a valid Segment object, and false
     * otherwise.
     */
    bool VerifyIntegrity() const
    {
        return magic_ == kSegmentMagic;
    }

    /**
     * This s a RAII style class used to automatically unmap a shared memory segment
     * upon destruction of its owner (Segment in this case).
     */
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
        /**
         * This status flag is set by the parent, to inform the child process
         * that the channel is now closed and the corresponding service thread
         * should stop.
         */
        kRequestHangUp,
    };

    AutoUnmapper autounmap_;
    volatile ChannelSide turn_;
    uint32_t             magic_ = kSegmentMagic;
    std::size_t          chan_sz_;
    SegmentStatus volatile status_{kActive};
    std::size_t memsz_;
};

/**
 * This is a wrapper around Segment. Both the server and the client use this
 * class to work with Segments.
 */
template<std::size_t SZ>
class SegmentDescriptor {
public:
    SegmentDescriptor(int fd, ChannelSide side, Segment<SZ>& seg, pid_t cp)
        : side_{side},
          segment_{seg},
          child_pid_{cp},
          fd_{fd}
    {
        /**
         * The named shared memory was used to establish a communication channel
         * the client and server processes. After the channel is connected, we
         * no longer need keep the named shared memory linked in /dev/shm.
         * We do the unlinking on the child (server) side after opening the channels.
         */
        std::string name = GenerateShMemName();
        GetSendChannel().status_ = kOpen;
    }

    SegmentDescriptor(int sndfd, int rcvfd, ChannelSide side, Segment<SZ>& seg, pid_t cp)
        : side_{side},
          segment_{seg},
          child_pid_{cp},
        /**
         * The named shared memory was used to establish a communication channel
         * the client and server processes. After the channel is connected, we
         * no longer need keep the named shared memory linked in /dev/shm.
         * We do the unlinking on the child (server) side after opening the channels.
         */
          fd_{-1},
          send_{sndfd},
          recv_{rcvfd}
    {

        GetSendChannel().status_ = kOpen;
    }

    SegmentDescriptor(SegmentDescriptor const& sd) = delete;
    SegmentDescriptor(SegmentDescriptor&& sd) = delete;
    SegmentDescriptor& operator=(SegmentDescriptor const& sd) = delete;
    SegmentDescriptor& operator=(SegmentDescriptor&& sd) = delete;

    ~SegmentDescriptor()
    {
        GetSendChannel().status_ = kClosed;
        Switch();
        segment_.~Segment();
        if (fd_ > -1) {
            close(fd_);
        }
    }

    template <typename... Args>
    void
    SendRequest(Args... args)
    {
        Unroll(std::data(GetSendChannel()), SZ, args...);
        Switch();
    }

    /**
     * Lay out a series of values of type Args... in a memory segment with
     * appropriate alignment. This method is called recursively.
     * 
     * @param  base: The starting address of the memory segment.
     * @param  remaining_chan_space: size of available memory left in the segment
     * @param  t: The first value in the series of type T
     * @param  args: The reset of the values of types Args...
     */
    template <typename T, typename... Args>
    void
    Unroll(std::byte* base, std::size_t remaining_chan_space, T t, Args... args)
    {
        PROXY_LOG(DBG) << "Unroll: " << base << "  <-- " << t << std::endl;
        /**
         * We handle character strings differently from other types.
         */
        if constexpr (std::is_same<T, std::string>::value) {
            char* base_param = reinterpret_cast<char*>(base);
            strcpy(base_param, t.c_str());
            std::string::size_type strlen = t.size();
            base += strlen;
            if (strlen <= remaining_chan_space)
                remaining_chan_space -= strlen;
            else
                remaining_chan_space = 0;
            // Move the base pointer to the next usable address with an alignment
            // of at least 8 bytes.
            auto ret = std::align(kSHMAlignment, 1, reinterpret_cast<void*&>(base), remaining_chan_space);
            // If std::align returns nullptr it means that the buffer does not have
            // enought space to hold all of the arguments.
            if (ret == nullptr)
                throw SendBufferOverflow{};
        } else {
            T* base_param = reinterpret_cast<T*>(base);
            *base_param = t;
            base += sizeof(T);
            if (sizeof(T) <= remaining_chan_space)
                remaining_chan_space -= sizeof(T);
            else
                remaining_chan_space = 0;
            // Move the base pointer to the next usable address with an alignment
            // of at least 8 bytes.
            auto ret = std::align(kSHMAlignment, 1, reinterpret_cast<void*&>(base), remaining_chan_space);
            // If std::align returns nullptr it means that the buffer does not have
            // enought space to hold all of the arguments.
            if (ret == nullptr)
                throw SendBufferOverflow{};
        }

        if constexpr (sizeof...(args) > 0)
            Unroll(base, remaining_chan_space, args...);
    }

    /**
     * This method block until it's current process's turn and then extracts
     * values of type tuple T from current channel's receive memory segment.
     * 
     * @retval A tuple of type T containing the extracted values.
     */
    template <typename T>
    auto
    ExtractParams()
    {
        PROXY_LOG(DBG) << ((side_ == kParent) ? "Parent" : "Child")
                       << " is waiting for its turn" << std::endl;
        Wait();
        if (side_ == kChild && segment_.HangUpRequested()) {
            PROXY_LOG(DBG) << "Child: Got HangUp request1" << std::endl;
            throw HangUpRequest{};
        }
        PROXY_LOG(DBG) << ((side_ == kParent) ? "Parent" : "Child")
                       << " is going to extract" << std::endl;
        return segment_.template ExtractParams<T>(std::data(GetRecvChannel()));
    }

    Channel<SZ>& GetSendChannel()
    {
        return ((side_ == kParent) ? send_ : recv_);
    }

    Channel<SZ>& GetRecvChannel()
    {
        return ((side_ == kParent) ? recv_ : send_);
    }

    /**
     * Block until it is our turn again on this segment descriptor, or the process
     * on the other side of the channel has exited, in which case an exception is
     * thrown: ChildTerminated and ParentTerminated exceptions in the parent and
     * child process, respectively.
     */
    void
    Wait()
    {
        if (side_ == kParent) {
            while(segment_.turn_ == kChild) {
                _mm_pause();
                //XXX
                usleep(1);
                if (has_child_terminated(child_pid_)) {
                    segment_.turn_ = kParent;
                    throw ChildTerminated{};
                }
            }
        } else if (side_ == kChild) {
            while(segment_.turn_ == kParent) {
                _mm_pause();
                //XXX
                usleep(1);
                if (has_parent_terminated()) {
                    throw ParentTerminated{};
                }
            }
        }
    }

    /**
     * Pass the turn for this communication channel to the other side (process)
     */
    void
    Switch()
    {
        segment_.turn_ = (segment_.turn_ == kParent) ? kChild : kParent;
    }
   
    Segment<SZ>&
    GetSegment() const
    {
        return segment_;
    }

    /**
     * This method is called on the server (child) side to determine if the parent
     * has requested it to hang up (end) this channel.
     */
    bool
    HangUpRequested()
    {
        return segment_.HangUpRequested();
    }

    int
    GetSegFd() { return fd_; }

    int
    GetSndFd() { return send_.GetFd(); }

    int
    GetRcvFd() { return recv_.GetFd(); }

private:
    ChannelSide     side_;
    Segment<SZ>&    segment_;
    pid_t           child_pid_;
    Channel<SZ>     send_;
    Channel<SZ>     recv_;
    int             fd_;
};

/**
 * Stub is used by the client to call upon the server. The stub
 * redirects such calls to the server and extracts and parses
 * the response and returns it to the caller.
 */
template<std::size_t SZ>
class Stub {
public:
    Stub(SegmentDescriptor<SZ>& segd)
        : segd_{segd}
    { }

    Stub(Stub const& s) = delete;
    Stub(Stub&& s) = delete;
    Stub& operator=(Stub const& s) = delete;
    Stub& operator=(Stub&& s) = delete;

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
    SegmentDescriptor<SZ>& segd_;
};

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
        // The function that the service thread should execute
        void* service_func;
        CommandCode code;
        int segfd;
        int sndfd;
        int rcvfd;
    };
};

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
    AbstractProxy()
    {
        CreateManagementSockets();
        StartServer();
        status_ = kProxyActive;
    }

    AbstractProxy(AbstractProxy const& ap) = delete;
    AbstractProxy(AbstractProxy&& ap) = delete;
    AbstractProxy& operator=(AbstractProxy const& ap) = delete;
    AbstractProxy& operator=(AbstractProxy&& ap) = delete;

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
                exit(EC_OK);
            } catch (HangUpRequest&) {
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
            exit(EC_MAN_SOCK_WRITE_SHUTDOWN);
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
    SendNewChannelInfo(int segfd, int sndfd, int rcvfd, SFUNC service_func)
    {
        Command cmd;
        cmd.service_func = reinterpret_cast<void*>(service_func);
        cmd.code = kNewChannel;

        struct msghdr msg;
        struct cmsghdr *cmsghdr;
        struct iovec iov[1];
        int* p;
        union {
            struct cmsghdr hdr;
            unsigned char  buf[CMSG_SPACE(sizeof(int) * 3)];
        } cmsgbuf;

        iov[0].iov_base = &cmd;
        iov[0].iov_len = sizeof(cmd);
        memset(&cmsgbuf.buf, 0x0b, sizeof(cmsgbuf.buf));
        cmsghdr = &cmsgbuf.hdr;
        cmsghdr->cmsg_len = CMSG_LEN(sizeof(int) * 3);
        cmsghdr->cmsg_level = SOL_SOCKET;
        cmsghdr->cmsg_type = SCM_RIGHTS;
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = iov;
        msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
        msg.msg_control = cmsghdr;
        msg.msg_controllen = sizeof(cmsgbuf.buf);
        msg.msg_flags = 0;
        p = (int*)CMSG_DATA(cmsghdr);
        *p       =  segfd;
        *(p + 1) =  sndfd;
        *(p + 2) =  rcvfd;

        int ret = sendmsg(GetCommandSocket(), &msg, 0);
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
    OpenChannel(ChannelSide side)
    {
        /**
         * Calculate the minumum possible size for the shared memory segment.
         */
        std::size_t seg_memsz = div_round_up(sizeof(Segment<SZ>), kPageSize);

        auto [m, fd] = open_map_shm(seg_memsz);
        Segment<SZ>* seg = new (m) Segment<SZ>{side == kParent, seg_memsz};
        auto segd = new SegmentDescriptor<SZ>(fd, side, *seg, child_pid_);
        return segd;
    }

    SegmentDescriptor<SZ>*
    OpenChannel(int segfd, int sndfd, int rcvfd, ChannelSide side)
    {
        /**
         * Calculate the minumum possible size for the shared memory segment.
         */
        std::size_t seg_memsz = div_round_up(sizeof(Segment<SZ>), kPageSize);

        void* m = open_map_shm(segfd, seg_memsz);
        int ret = close(segfd);
        if (ret == -1)
            PROXY_LOG(DBG) << "Cannot close segfd in child" << std::endl;
        Segment<SZ>* seg = new (m) Segment<SZ>{side == kParent, seg_memsz};
        auto segd = new SegmentDescriptor<SZ>(sndfd, rcvfd, side, *seg, child_pid_);
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
                PROXY_LOG(DBG) << "Child: Got command: kNewChannel - fds: "
                               << cmd->segfd << " "
                               << cmd->sndfd << " "
                               << cmd->rcvfd << std::endl;
                // Extract the service function from the Command object
                using WT = void(*)(decltype(this), SegmentDescriptor<SZ>*);
                WT service_func;
                service_func = reinterpret_cast<WT>(cmd->service_func);
                // Extract the name of the segment descriptor from the Command
                // object and open it.
                SegmentDescriptor<SZ>* segd;
                segd = OpenChannel(cmd->segfd,
                                   cmd->sndfd,
                                   cmd->rcvfd,
                                   kChild);
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
                exit(EC_OK);
                break;
            }
        }
        PROXY_LOG(INF) << "Child command loop terminated." << std::endl;
        exit(EC_CHILD_LOOP_TERMINATED);
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
        struct msghdr msg;
        struct cmsghdr *cmsghdr;
        struct iovec iov[1];
        int* p;
        union {
            struct cmsghdr hdr;
            unsigned char  buf[CMSG_SPACE(sizeof(int) * 3)];
        } cmsgbuf;
        iov[0].iov_base = cmd;
        iov[0].iov_len = sizeof(*cmd);
        memset(&cmsgbuf.buf, 0x0d, sizeof(cmsgbuf.buf));
        cmsghdr = &cmsgbuf.hdr;
        cmsghdr->cmsg_len = CMSG_LEN(sizeof(int) * 3);
        cmsghdr->cmsg_level = SOL_SOCKET;
        cmsghdr->cmsg_type = SCM_RIGHTS;
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = iov;
        msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
        msg.msg_control = &cmsgbuf.buf;
        msg.msg_controllen = sizeof(cmsgbuf.buf);
        msg.msg_flags = 0;
        int ret = recvmsg(GetCommandSocket(), &msg, 0);
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
        p = (int*)CMSG_DATA(cmsghdr);
        cmd->segfd = *p;
        cmd->sndfd = *(p + 1);
        cmd->rcvfd = *(p + 2);
        return std::shared_ptr<Command>(cmd);
    }

    int
    GetCommandSocket() const
    {
        return (side_ == kParent) ? cmd_ch_[0] : cmd_ch_[1];
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
            exit(EC_SOCKETPAIR_CREATION);
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
            exit(EC_FORK_FAILED);
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

        Execution(Execution const& e) = delete;
        Execution(Execution& e) = delete;
        Execution& operator=(Execution const& e) = delete;
        Execution& operator=(Execution&& e) = delete;

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
                PROXY_LOG(DBG) << "+ New segment descriptor" << std::endl;
                segd_ = proxy_->OpenChannel(kParent);
                stub_ = new Stub<SZ>(*segd_);
                auto service_func =
                    &AbstractProxyWorkLoopWrapper<decltype(proxy_), SZ, RET, Args...>;
                proxy_->SendNewChannelInfo(segd_->GetSegFd(),
                                           segd_->GetSndFd(),
                                           segd_->GetRcvFd(),
                                           service_func);
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
                for (auto& e : executions)
                    delete std::get<1>(e);
                executions.clear();
                execution->Shutdown();
                delete execution;
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
        static_assert(CalcBufSize<Args...>() <= SZ, "SZ is too small for Args");
        static_assert(CalcBufSize<RET>() <= SZ, "SZ is too small for RET");

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
     * A mapping from Segment Descriptors to the threads responsible for
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
    ProxyDirect() noexcept
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
    static ProxyDirect<SZ, SERV>&
    Build()
    {
        auto proxy = new ProxyDirect<SZ, SERV>{};
        proxy->BlockChildOnCommandLoop();
        return *proxy;
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
    static ProxySO<SZ>&
    Build(std::string dso_path)
    {
        auto proxy = new ProxySO<SZ>{dso_path};
        proxy->BlockChildOnCommandLoop();
        return *proxy;
    }

};

}
