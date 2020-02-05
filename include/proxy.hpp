/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2019, Amin Saba (amn.brhm.sb@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#if defined(__FreeBSD__) && defined(Proxy_CapabilityMode)
#include <sys/capsicum.h>
#endif
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/resource.h>

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
#include <any>
#include <gsl/pointers>

#include <dlfcn.h>
#include <immintrin.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define PXNOINT(c) ({                               \
    int _ret;                                       \
    do { _ret = (c); }                              \
    while (_ret == -1 && errno == EINTR);           \
    _ret;                                           \
    })

#define PROXY_LOG(c) PROXY_LOG_##c
#define PROXY_LOG_ERR std::cerr
#define PROXY_LOG_DBG std::cerr
// #define PROXY_LOG_DBG null_stream
#define PROXY_LOG_INF std::cerr

namespace capsiproxy {

class ParentTerminated:                         public std::exception {};
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
class SharedMemoryCreationInParentFailed:       public std::exception {};
class SharedMemoryUnlinkingInParentFailed:      public std::exception {};
class QueryFailed:                              public std::exception {};
class CreatingSocketPairFailed:                 public std::exception {};
class LimitingCapabiliteisFailed:		public std::exception {};
class WritingToCommandSocketFailed:             public std::exception {};
class SendChannelInfoFailed:                    public std::exception {};
class ForkFailed:                               public std::exception {};
class ChildTerminated:                          public std::exception {
public:
    ChildTerminated(int ec, rusage ru)
        : exit_code_{ec},
          ru_{ru} {}
    virtual char const* what() const noexcept {
        return (std::string{"Child exited with code: "} +
                std::to_string(exit_code_)).c_str();
    }
private:
    int exit_code_;
    rusage ru_;
};

namespace detail {

enum ExitCodes {
    EC_OK                               = 0,
    EC_SHM_SEG_CREATE                   = 10,
    EC_SHM_SEG_TRUNCATE                 = 20,
    EC_SHM_SEG_MAP                      = 30,
    EC_SHM_SEG_UNLINK                   = 40,
    EC_SIGNAL_LIVECHECK_INSTALLATION    = 50,
    EC_MAN_SOCK_WRITE_SHUTDOWN          = 60,
    EC_CHILD_LOOP_TERMINATED            = 70,
    EC_SOCKETPAIR_CREATION              = 80,
    EC_FORK_FAILED                      = 90,
    EC_ChildLoopFinishedWithError       = 100,
    EC_Opening_DSO_Failed               = 110,
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

enum MapMode {
	CH_READ,
	CH_WRITE,
	CH_READ_WRITE,
};

/**
 * The utils namespace holds a bunch of utility stand-alone functions used
 * internally by the implemenation.
 */
inline namespace utils {
inline bool has_parent_terminated() noexcept;
std::tuple<void*, int> open_map_shm(std::size_t sz);
void* open_map_shm(int fd, std::size_t sz, MapMode mm) noexcept;
std::tuple<void*, int> open_map_shm(std::size_t sz);
std::string GenerateRandomString(std::string::size_type length) noexcept;
std::string GenerateShMemName();

template<typename T>
struct remove_first_type
{};

template<typename T, typename... Ts>
struct remove_first_type<std::tuple<T, Ts...>>
{
    using type = std::tuple<Ts...>;
};

/**
 * Round up x to the smallest multiple of y.
 * @param  x: The value to be rounded up
 * @param  y: The multiplier
 * @retval Returns the smallest integral value that is greater than or equal to
 * x, and is a multiple of y
 */
inline std::size_t
div_round_up(std::size_t x, std::size_t y) noexcept
{
    return y * (1 + (x - 1) / y);
}

/**
 * Determines if the parent process of the current process has terminated.
 */
inline
bool has_parent_terminated() noexcept
{
    /** If our parent is the init process (PID 1), then our parent has already
     *  exited.
     */
     return getppid() == 1;
}

#if defined(__FreeBSD__) && defined(Proxy_CapabilityMode)
/**
 * Limit the 'fd' file descriptor so that it can only be used as dicated by
 * the rights in 'rights_list'.
 * 
 * @param  fd: The file descriptor to be limited
 * @param  rights_list: A list of requested rights
 */
void
limit_fd(int fd, std::initializer_list<uint64_t> rights_list)
{
    cap_rights_t rights;
    cap_rights_init(&rights);
    for (auto r : rights_list)
	    cap_rights_set(&rights, r);
    int ret = cap_rights_limit(fd, &rights);
    if (ret == -1) {
#ifdef PROXY_DEBUG
	PROXY_LOG(DBG) << "Cannot limit capabilites for fd: " << fd << std::endl;
#endif
	throw LimitingCapabiliteisFailed{};
    }
}

/**
 * Limit the `sofd` file descriptor to the dynamic shared object that is to be
 * passed to the sandbox process, so that it can only be mapped with READ_EXECUTE
 * permission and can also be fstat()ed. This prevents the sandboxed process
 * from making any changes to the file.
 * 
 * @retval The new file descriptor (capability) to be pass to the server.
 */
uint64_t
limit_dso_fd(int sofd)
{
    /**
     * We should duplicated the file descriptor, otherwise the limitations will
     * also apply to the parent (client) process.
     */    
    uint64_t fd = fcntl(sofd, F_DUPFD);
    limit_fd(fd, {CAP_MMAP_RX, CAP_FSTAT});
    return fd;
}

/**
 * Limit the `segfd` file descriptor to the shared memory object we want to
 * pass to the sandbox process, so that it can only be mapped with READ_WRITE
 * permission.
 * 
 * @retval The new file descriptor (capability) to be pass to the server.
 */
uint64_t
limit_seg_fd(int segfd)
{
    /**
     * We should duplicated the file descriptor, otherwise the limitations will
     * also apply to the parent (client) process.
     */    
    uint64_t fd = fcntl(segfd, F_DUPFD);
    limit_fd(fd, {CAP_MMAP_RW, CAP_FTRUNCATE});
    return fd;
}

/**
 * Limit the `sndvfd` file descriptor to the shared memory object we want to
 * pass to the sandbox process, so that it can only be mapped with READ_ONLY
 * permission.
 * 
 * @retval The new file descriptor (capability) to be pass to the server.
 */
uint64_t
limit_send_fd(int sndfd)
{
    /**
     * We should duplicated the file descriptor, otherwise the limitations will
     * also apply to the parent (client) process.
     */    
    uint64_t fd = fcntl(sndfd, F_DUPFD);
    limit_fd(fd, {CAP_MMAP_R, CAP_FTRUNCATE});
    return fd;
}

/**
 * Limit the `recvfd` file descriptor to the shared memory object we want to
 * pass to the sandbox process, so that it can only be mapped with WRITE_ONLY
 * permission.
 * 
 * @retval The new file descriptor (capability) to be pass to the server.
 */
uint64_t
limit_recv_fd(int rcvfd)
{
    /**
     * We should duplicated the file descriptor, otherwise the limitations will
     * also apply to the parent (client) process.
     */    
    uint64_t fd = fcntl(rcvfd, F_DUPFD);
    limit_fd(fd, {CAP_MMAP_W, CAP_FTRUNCATE});
    return fd;
}
#endif

/**
 * Just an ad-hoc method to have a short period of busy waiting followed by
 * sleeping to minimize CPU usage while remaining agile for fast back-to-back
 * requests.
 * @param  reset: Reset the method back to busy waiting.
 */
__always_inline
void adaptive_wait(bool reset = false)
{
    //XXX: chose some system dependent value for kThreshold
    constexpr uint64_t kThreshhold = 2000'000;
    static uint64_t cnt = 0;
    if (reset)
        cnt = 0;
    if (cnt <= kThreshhold) {
        cnt++;
        _mm_pause();
    }
    else
        usleep(10000);
}

/**
 * This is used by the child (server) process to verify that its parent
 * (client) process is still running, and exits the child process
 * otherwise with an exit code of EC_SIGNALO_LIVECHECK_INSTALLATION.
 */
extern "C"
void
sig_livecheck_handler(int signo) noexcept
{
    if (has_parent_terminated())
    {
#ifdef PROXY_DEBUG
        PROXY_LOG(INF) << "Child: parent terminated.";
#endif
        exit(EC_SIGNAL_LIVECHECK_INSTALLATION);
    }
}

std::string
GenerateRandomString(std::string::size_type length) noexcept
{
    std::string result;
    static char* chars = "0123456789"
                         "abcdefghijklmnopqrstuvwxyz"
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static std::mt19937 randgen{std::random_device{}()};
    static std::uniform_int_distribution<std::string::size_type>
                         selector(0, sizeof(chars) - 2);
    while(length--)
        result += chars[selector(randgen)];
    return result;
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
auto pop_front_impl(const Tuple& tuple, std::index_sequence<Is...>) noexcept
{
    return std::make_tuple(std::get<1 + Is>(tuple)...);
}
template <typename Tuple>
auto pop_front(const Tuple& tuple) noexcept
{
    return pop_front_impl(tuple,
                          std::make_index_sequence<
                                std::tuple_size<Tuple>::value - 1>());
}

/**
 * Auxiliary function to open a shared memory segment and map it into the address
 * space of the current process.
 * @param  fd: A file descriptor (capbaility) to a shared memory segment.
 * @param  sz: The size of the shared memory segment.
 * @param  mm: The mode (read/write) in which the memory should be mapped.
 * @retval Upon success this function returns a void* pointer to the beginning
 * of the shared memory segment.
 */
void*
open_map_shm(int fd, std::size_t sz, MapMode mm = CH_READ_WRITE) noexcept
{
    int ret = ftruncate(fd, sz);
    if (ret == -1) {
        PROXY_LOG(ERR) << "Cannot ftruncate shared memory for segment" << std::endl;
        perror("ftruncate");
        exit(EC_SHM_SEG_TRUNCATE);
    }
    int flags;
    switch (mm) {
    case CH_READ:
	flags = PROT_READ;
	break;
    case CH_WRITE:
	flags = PROT_WRITE;
	break;
    case CH_READ_WRITE:
	flags = PROT_READ | PROT_WRITE;
	break;
    }
    void* m = mmap(nullptr, sz, flags, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) {
        PROXY_LOG(ERR) << "Cannot map shared memory for segment" << std::endl;
	perror("mmap");
        exit(EC_SHM_SEG_MAP);
    }
    return m;
}

/**
 * Auxiliary function to open a shared memory segment and map it into the address
 * space of the current process. A unique random string is used to create the
 * POSIX named shared memory segment.
 * @param  sz: The size of the shared memory segment.
 * @retval Upon success this function returns a void* pointer to the beginning
 * of the shared memory segment, and a file descriptor to the shared memory
 * segment.
 */
std::tuple<void*, int>
open_map_shm(std::size_t sz)
{
    auto name = detail::GenerateShMemName();
    int fd = shm_open(name.c_str(), O_RDWR | O_CREAT, S_IRWXU);
    if (fd == -1) {
        PROXY_LOG(ERR) << "Cannot create shared memory for segment";
        PROXY_LOG(ERR) << "shm_open: " << strerror(errno) << std::endl;
        throw SharedMemoryCreationInParentFailed{};
    }
    auto ptr = open_map_shm(fd, sz);
    /**
     * We no longer need the this named shared memory in /dev/shm. So we just
     * unlink it immediately. The server process will open this shared memory
     * via the file descriptor we send to it.
     */
    int ret = shm_unlink(name.c_str());
    if (ret) {
        PROXY_LOG(ERR) << "Cannot unlink the shared memory of segment";
        PROXY_LOG(ERR) << "shm_unlink: " << strerror(errno) << std::endl;
        throw SharedMemoryUnlinkingInParentFailed{};
    }
    return std::make_tuple(ptr, fd);
}

/**
 * Check if a given child process has exited for any reason.
 * @param  cp: PID of the child process.
 */
std::tuple<bool,int,rusage>
has_child_terminated(pid_t cp) noexcept
{
    int status;
    rusage ru;
    int ret = PXNOINT(wait4(cp, &status, WNOHANG, &ru));
    if (ret > 0 && (WIFEXITED(status)   ||
                    WIFSIGNALED(status) ||
                    WIFSTOPPED(status)))  {
        return std::make_tuple(true, WEXITSTATUS(status), ru);
    }
    return std::make_tuple(false, 0, ru);
}

/**
 * Calculate the size of the shared memory buffer needed to contain the parameters
 * Args...
 */
template <typename T>
constexpr std::size_t
CalcBufSize() noexcept
{
    if constexpr (std::is_same<std::string, T>::value)
        return 8;
    else
        return 8;
}

template <typename T, typename U, typename... Args>
constexpr std::size_t
CalcBufSize() noexcept
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
#ifdef PROXY_DEBUG
        PROXY_LOG(DBG) << "Created channel fd: " << fd << " size: " << SZ << std::endl;
#endif
        base_ = reinterpret_cast<std::byte*>(ptr);
    }

    Channel(int fd, MapMode mm) noexcept
        : fd_{fd}
    {
#ifdef PROXY_DEBUG
        PROXY_LOG(DBG) << "Creating channel - fd: " << fd << " size: "
                       << SZ << std::endl;
#endif
        auto ptr = open_map_shm(fd, SZ, mm);
        base_ = reinterpret_cast<std::byte*>(ptr);
    }

    ~Channel() noexcept
    {
        if (fd_ < 0)
            return;
#ifdef PROXY_DEBUG
        PROXY_LOG(DBG) << "Destructing channel. fd: " << fd_ << std::endl;
#endif
        int ret = PXNOINT(close(fd_));
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
    data() noexcept
    {
        return base_;
    }

    int
    GetFd() const noexcept
    {
        return fd_;
    }

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
        : chan_sz_{SZ},
          memsz_{memsz}
    {
        if (!init_turn) {
            if (!VerifyIntegrity())
                throw BadSegment{};
        } else {
            turn_ = kParent;
        }
    }

    Segment(Segment const& s) = delete;
    Segment(Segment&& s) = delete;
    Segment& operator=(Segment const& s) = delete;
    Segment& operator=(Segment&& s) = delete;

    /**
     * Determines if currently its the client's turn in this channel.
     */
    __always_inline
    bool ParentTurn() noexcept
    {
        return turn_ == kParent;
    }

    __always_inline
    bool ChildTurn() noexcept
    {
        return !ParentTurn();
    }

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
        assert(chan_start != nullptr);
        /**
         * Generate the body of method only if there are enought many
         * elements in the ruple.
         */
        if constexpr (std::tuple_size<TUP>::value >= N + 1)
        {
            using TYPE = std::tuple_element_t<N, TUP>;
            /**
             * Since strings can have arbitrary length, they need special
             * treatment. The string must be null-terminated.
             */
            if constexpr (std::is_same<TYPE, std::string>::value) {
                auto ret = std::align(kSHMAlignment, 1,
                                      reinterpret_cast<void*&>(chan_start),
                                      chan_sz_);
                if (ret == nullptr)
                    throw ExtractionBufferOverflow{};
                char* item = reinterpret_cast<char*>(chan_start);
#ifdef PROXY_DEBUG
                PROXY_LOG(DBG) << "Extracted string value: " << item
                               << std::endl;
#endif
                std::string item_str {item};
                std::string::size_type item_sz = item_str.size();
                /**
                 * Put the extracted string into the results tuple.
                 */
                std::get<N>(instance) = item_str;
                /**
                 * Update chan_start and chan_sz_ to pass the extracted value.
                 * The starting address for the next value will be calculated
                 * using std::align in the next iteration/call.
                 */
                chan_start += (item_sz + 1);
                if (item_sz <= chan_sz_)
                    chan_sz_ -= (item_sz + 1);
                else
                    chan_sz_ = 0;

            } else { // Any thing other than a std::string

                auto ret = std::align(kSHMAlignment, 1,
                                      reinterpret_cast<void*&>(chan_start),
                                      chan_sz_);
                if (ret == nullptr)
                    throw ExtractionBufferOverflow{};
                std::add_pointer_t<TYPE> p0;
                auto item = reinterpret_cast<decltype(p0)>(chan_start);
#ifdef PROXY_DEBUG
                PROXY_LOG(DBG) << "Extracted non-string value: " << *item
                               << std::endl;
#endif
                /**
                 * Put the extracted string into the results tuple.
                 */
                std::get<N>(instance) = *item;
                /**
                 * Update chan_start and chan_sz_ to pass the extracted value.
                 * The starting address for the next value will be calculated
                 * using std::align in the next iteration/call.
                 */
                chan_start += sizeof(item);
                if (sizeof(item) <= chan_sz_)
                    chan_sz_ -= sizeof(item);
                else
                    chan_sz_ = 0;
            }
        }
    }

    /**
     * Extract parameters with types as types of tuple T. This method assumes
     * that tuple T has at most 16 elements.
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
#ifdef PROXY_DEBUG
        PROXY_LOG(DBG) << "ExtractParams: " << buf << std::endl;
#endif
        T tup;
        static_assert(std::tuple_size<T>::value < 17);
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
    GetSize() noexcept
    {
        return memsz_;
    }
    
    bool
    HangUpRequested() noexcept
    {
        return status_ == kRequestHangUp;
    }

    ~Segment() noexcept
    {
        // Inform the child (server) thread that the channel is closed.
        status_ = kRequestHangUp;
#ifdef PROXY_DEBUG
        PROXY_LOG(DBG) << "Destructing segment";
#endif
    }

private:
    /**
     * The server process uses this method to verify that the mapped memory for
     * the Segment, contains a valid and already initialized Segment object.
     * @retval Returns true if it detects a valid Segment object, and false
     * otherwise.
     */
    bool VerifyIntegrity() const noexcept
    {
        return magic_ == kSegmentMagic;
    }

    enum SegmentStatus {
        kActive,
        /**
         * This status flag is set by the parent, to inform the child process
         * that the channel is now closed and the corresponding service thread
         * should stop.
         */
        kRequestHangUp,
    };

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

    SegmentDescriptor(int sndfd, int rcvfd, ChannelSide side,
                      Segment<SZ>& seg, pid_t cp) noexcept
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
          send_{sndfd, CH_READ},
          recv_{rcvfd, CH_WRITE}
    {

        GetSendChannel().status_ = kOpen;
    }

    SegmentDescriptor(SegmentDescriptor const& sd) = delete;
    SegmentDescriptor(SegmentDescriptor&& sd) = delete;
    SegmentDescriptor& operator=(SegmentDescriptor const& sd) = delete;
    SegmentDescriptor& operator=(SegmentDescriptor&& sd) = delete;

    ~SegmentDescriptor() noexcept
    {
        GetSendChannel().status_ = kClosed;
        Switch();
        segment_.~Segment();
        if (fd_ > -1) {
            PXNOINT(close(fd_));
        }
    }

    template <typename... Args>
    void
    SendRequest(Args... args)
    {
        if constexpr (sizeof...(Args) > 0)
            Unroll(gsl::make_not_null(std::data(GetSendChannel())), SZ, args...);
        Switch();
    }

    /**
     * Lay out a series of values of type Args... in a memory segment with
     * appropriate alignment. This method is called recursively.
     * 
     * @param  basenn: The starting address of the memory segment.
     * @param  remaining_chan_space: size of available memory left in the segment
     * @param  t: The first value in the series of type T
     * @param  args: The reset of the values of types Args...
     */
    template <typename T, typename... Args>
    void
    Unroll(gsl::not_null<std::byte*> basenn, std::size_t remaining_chan_space,
           T t, Args... args)
    {
        auto base = basenn.get();
#ifdef PROXY_DEBUG
        PROXY_LOG(DBG) << "Unroll: " << base << "  <-- " << t << std::endl;
#endif
        /**
         * We handle character strings differently from other types.
         */
        if constexpr (std::is_same<T, std::string>::value) {
            /*
             * Move the base pointer to the next usable address with an alignment
             * of at least 8 bytes.
             */
            auto ret = std::align(kSHMAlignment, t.size() + 1,
                                  reinterpret_cast<void*&>(base),
                                  remaining_chan_space);
            if (ret == nullptr)
                throw SendBufferOverflow{};
            char* base_param = reinterpret_cast<char*>(base);
            strcpy(base_param, t.c_str());
            std::string::size_type strlen = t.size();
            /**
             * Update base and remaining_chan_space for next iteration.
             */
            base += (strlen + 1);
            if (strlen <= remaining_chan_space)
                remaining_chan_space -= strlen;
            else
                remaining_chan_space = 0;
        } else {
            /*
             * Move the base pointer to the next usable address with an alignment
             * of at least 8 bytes.
             */
            auto ret = std::align(kSHMAlignment, 8, reinterpret_cast<void*&>(base),
                                  remaining_chan_space);
            if (ret == nullptr)
                throw SendBufferOverflow{};
            T* base_param = reinterpret_cast<T*>(base);
            *base_param = t;
            /**
             * Update base and remaining_chan_space for next iteration.
             */
            base += sizeof(T);
            if (sizeof(T) <= remaining_chan_space)
                remaining_chan_space -= sizeof(T);
            else
                remaining_chan_space = 0;
        }

        if constexpr (sizeof...(args) > 0)
            Unroll(gsl::make_not_null(base), remaining_chan_space, args...);
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
#ifdef PROXY_DEBUG
        PROXY_LOG(DBG) << ((side_ == kParent) ? "Parent" : "Child")
                       << " is waiting for its turn" << std::endl;
#endif
        Wait();
        if (side_ == kChild && segment_.HangUpRequested()) {
#ifdef PROXY_DEBUG
            PROXY_LOG(DBG) << "Child: Got HangUp request [1]" << std::endl;
#endif
            throw HangUpRequest{};
        }
#ifdef PROXY_DEBUG
        PROXY_LOG(DBG) << ((side_ == kParent) ? "Parent" : "Child")
                       << " is going to extract" << std::endl;
#endif
        return segment_.template ExtractParams<T>(std::data(GetRecvChannel()));
    }

    Channel<SZ>& GetSendChannel() noexcept
    {
        return ((side_ == kParent) ? send_ : recv_);
    }

    Channel<SZ>& GetRecvChannel() noexcept
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
        adaptive_wait(true);
        if (side_ == kParent) {
            while(segment_.turn_ == kChild) {
                adaptive_wait(false);
                auto [yes, exitcode, usage] = has_child_terminated(child_pid_);
                if (yes) {
                    segment_.turn_ = kParent;
#ifdef PROXY_DEBUG
                    PROXY_LOG(DBG) << "Child Terminated with exit code: " << exitcode << std::endl;
#endif
                    throw ChildTerminated{exitcode, usage};
                }
            }
        } else if (side_ == kChild) {
            while(segment_.turn_ == kParent) {
                adaptive_wait(false);
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
    Switch() noexcept
    {
        segment_.turn_ = (segment_.turn_ == kParent) ? kChild : kParent;
    }

    Segment<SZ>&
    GetSegment() const noexcept
    {
        return segment_;
    }

    /**
     * This method is called on the server (child) side to determine if the parent
     * has requested it to hang up (end) this channel.
     */
    bool
    HangUpRequested() const noexcept
    {
        return segment_.HangUpRequested();
    }

    int
    GetSegFd() const noexcept
    {
        return fd_;
    }

    int
    GetSndFd() const noexcept
    {
        return send_.GetFd();
    }

    int
    GetRcvFd() const noexcept
    {
        return recv_.GetFd();
    }

private:
    ChannelSide     side_;
    Segment<SZ>&    segment_;
    pid_t           child_pid_;
    int             fd_;
    Channel<SZ>     send_;
    Channel<SZ>     recv_;
};

/**
 * Stub is used by the client to call upon the server. The stub
 * redirects such calls to the server and extracts and parses
 * the response and returns it to the caller.
 */
template<std::size_t SZ>
class Stub {
public:
    explicit Stub(SegmentDescriptor<SZ>& segd) noexcept
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

    explicit AbstractProxy(std::string soname)
    {
#if defined(__FreeBSD__) && defined(Proxy_CapabilityMode)
	/**
     * In case of FreeBSD and capsicum, we will use fdlopen() instead of
     * dlopen(). So just get a file desctriptor to the DSO and limit it.
	 */
	sofd_ = open(soname.c_str(), O_RDONLY, 0);
	sofd_ = limit_dso_fd(sofd_);
#endif
        CreateManagementSockets();
        StartServer();
        status_ = kProxyActive;
    }

    ~AbstractProxy() noexcept
    {
        using EXEMAPTYPE = std::map<void*, std::any>;
        try {
            for (auto kv : all_executions) {
                auto v = std::any_cast<EXEMAPTYPE*>(kv.second);
                auto iter = v->find(this);
                if (iter != v->end()) {
                    v->erase(iter);
                }
            }
        } catch (...) {
            PROXY_LOG(ERR) << "Exception was thrown when destructing "
                              "an instance of Proxy" << std::endl;
            // Will cause termination due to noexcept specification.
            throw;
        }
    }

    AbstractProxy(AbstractProxy const& ap) = default;
    AbstractProxy(AbstractProxy&& ap) = delete;
    AbstractProxy& operator=(AbstractProxy const& ap) = delete;
    AbstractProxy& operator=(AbstractProxy&& ap) = delete;

    /**
     * This function implements the service loop for each worker thread in the
     * child (server). For each channel there is exactly one thread that runs
     * this service loop with the types Args and RET appropriate for its
     * corresponding fucntion.
     * 
     * @tparam RET: The return type of the service function.
     * 
     * @tparam Args: The argument types of service function.
     * 
     * @param segd: A pointer to the appripriate segment descriptor.
     */
    template<typename RET, typename... Args>
    void
    StartServiceLoop(SegmentDescriptor<SZ>* segd) noexcept
    {
#ifdef PROXY_DEBUG
        PROXY_LOG(DBG) << "Starting Service Loop." << std::endl;
#endif
        while (true) {
            try {
                auto ins = segd->template ExtractParams<std::tuple<Args...>>();
                RET result = static_cast<SUB*>(this)->template Do<RET>(ins);
#ifdef PROXY_DEBUG
                PROXY_LOG(DBG) << "Child: Result ready: " << result << std::endl;
#endif
                // Send the result back to the parent process.
                segd->SendRequest(result);
            } catch (ParentTerminated& pte) {
#ifdef PROXY_DEBUG
                PROXY_LOG(DBG) << "Child: Parent terminated" << std::endl;
#endif
                exit(EC_OK);
            } catch (HangUpRequest&) {
#ifdef PROXY_DEBUG
                PROXY_LOG(DBG) << "Child: Got hangup request [2]" << std::endl;
#endif
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
    BlockChildOnCommandLoop() noexcept
    {
        if (side_ == kChild) {
            try {
                CommandServerLoop();
            } catch (...) {
                exit(EC_ChildLoopFinishedWithError);
            }
        }
    }

    /**
     * Instruct the child (server) corresponding to this instance of AbstractProxy
     * to shutdown and exit. This will stop all services provided by this instance
     * of server.
     */
    void
    ShutdownServer() const
    {
        Command cmd;
        cmd.code = kShutDownRequest;
#ifdef PROXY_DEBUG
        PROXY_LOG(DBG) << "Going to send Shutdown request to child" << std::endl;
#endif
        int ret = PXNOINT(write(GetCommandSocket(), &cmd, sizeof(cmd)));
        if (ret == -1) {
            PROXY_LOG(ERR) << "Cannot write kShutdown request";
            throw WritingToCommandSocketFailed{};
        }
    }

protected:

#define MESSAGE_HEADER_COMMON_SETUP(c,m,iov)                      \
        cmsghdr *cmsghdr;                                         \
        do {                                                      \
            union {                                               \
                struct cmsghdr hdr;                               \
                unsigned char  buf[CMSG_SPACE(sizeof(int) * 3)];  \
            } cmsgbuf;                                            \
            memset(&cmsgbuf.buf, 0x0d, sizeof(cmsgbuf.buf));      \
            cmsghdr = &cmsgbuf.hdr;                               \
            cmsghdr->cmsg_len = CMSG_LEN(sizeof(int) * 3);        \
            cmsghdr->cmsg_level = SOL_SOCKET;                     \
            cmsghdr->cmsg_type = SCM_RIGHTS;                      \
            m.msg_name = NULL;                                    \
            m.msg_namelen = 0;                                    \
            m.msg_iov = iov;                                      \
            m.msg_iovlen = 1;                                     \
            m.msg_control = &cmsgbuf.buf;                         \
            m.msg_controllen = sizeof(cmsgbuf.buf);               \
            m.msg_flags = 0;                                      \
        } while (0)

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
    SendNewChannelInfo(int segfd, int sndfd, int rcvfd, SFUNC service_func) const
    {
        Command cmd;
        cmd.service_func = reinterpret_cast<void*>(service_func);
        cmd.code = kNewChannel;
        msghdr msg;
        iovec iov[1];
        iov[0].iov_base = &cmd;
        iov[0].iov_len = sizeof(cmd);
        MESSAGE_HEADER_COMMON_SETUP(cmd,msg,iov);
        int* p = reinterpret_cast<int*>(CMSG_DATA(cmsghdr));
#if defined(__FreeBSD__) && defined(Proxy_CapabilityMode)
        segfd = limit_seg_fd(segfd);
        sndfd = limit_send_fd(sndfd);
        rcvfd = limit_recv_fd(rcvfd);
#endif
        *p       = segfd;
        *(p + 1) = sndfd;
        *(p + 2) = rcvfd;
        int ret = PXNOINT(sendmsg(GetCommandSocket(), &msg, 0));
        if (ret == -1) {
            PROXY_LOG(ERR) << "Cannot write kNewChannel request: "
                           << errno << std::endl;
            throw SendChannelInfoFailed{};
        }
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
    OpenChannel(ChannelSide side) const
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
    OpenChannel(int segfd, int sndfd, int rcvfd, ChannelSide side) const noexcept
    {
        /**
         * Calculate the minumum possible size for the shared memory segment.
         */
        std::size_t seg_memsz = div_round_up(sizeof(Segment<SZ>), kPageSize);

        void* m = open_map_shm(segfd, seg_memsz);
        int ret = PXNOINT(close(segfd));
        if (ret == -1) {
#ifdef PROXY_DEBUG
            PROXY_LOG(DBG) << "Cannot close segfd in child" << std::endl;
#endif
        }
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
#ifdef PROXY_DEBUG
        PROXY_LOG(DBG) << "Starting command loop for child." << std::endl;
#endif
        while (true) {
            auto cmd = WaitForCommand();
            switch (cmd.code)
            {
            /**
             * This command shows that a function of a specific type has been
             * invoked in the client for the first time. Thus the child process
             * should create the related channels and thread to be able to
             * handle requests of this type.
             */
            case kNewChannel:
#ifdef PROXY_DEBUG
                PROXY_LOG(DBG) << "Child: Got command: kNewChannel - fds: "
                               << cmd.segfd << " "
                               << cmd.sndfd << " "
                               << cmd.rcvfd << std::endl;
#endif
                // Extract the service function from the Command object
                using WT = void(*)(decltype(this), SegmentDescriptor<SZ>*);
                WT service_func;
                service_func = reinterpret_cast<WT>(cmd.service_func);
                // Extract the name of the segment descriptor from the Command
                // object and open it.
                SegmentDescriptor<SZ>* segd;
                segd = OpenChannel(cmd.segfd,
                                   cmd.sndfd,
                                   cmd.rcvfd,
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
#ifdef PROXY_DEBUG
                PROXY_LOG(DBG) << "Child: Got command: kHangUp" << std::endl;
#endif
                break;

            /**
             * The client (parent) has requested to shutdown/exit this child
             * (server) process completely.
             */
            case kShutDownRequest:
#ifdef PROXY_DEBUG
                PROXY_LOG(DBG) << "Child: Got command: kShutDown" << std::endl;
#endif
                exit(EC_OK);
                break;
            }
        }
#ifdef PROXY_DEBUG
        PROXY_LOG(INF) << "Child command loop terminated." << std::endl;
#endif
        exit(EC_CHILD_LOOP_TERMINATED);
    }

    /**
     * Send a management command to the child (server) process.
     * @param cmd: The command to be sent to the server.
     */
    void
    SendCommand(Command const& cmd) const
    {
        int ret = PXNOINT(write(GetCommandSocket(), reinterpret_cast<void const*>(&cmd),
                                sizeof(cmd)));
        if (ret == -1) {
#ifdef PROXY_DEBUG
                PROXY_LOG(INF) << "Client: Writing to command socket failed." << std::endl;
#endif
                throw ParentWrite2CommandSocketFailed{};
        }
    }

    /**
     * The child (server) process call this method to block and wait for management
     * commands from the parent (client) process.
     */
    Command
    WaitForCommand() const
    {
        Command cmd;
        msghdr msg;
        iovec iov[1];
        iov[0].iov_base = &cmd;
        iov[0].iov_len = sizeof(cmd);
        MESSAGE_HEADER_COMMON_SETUP(cmd,msg,iov);
        int ret = PXNOINT(recvmsg(GetCommandSocket(), &msg, 0));
        if (ret == -1) {
            PROXY_LOG(ERR) << "Cannot read from kNewChannel request" << std::endl;
            throw ChildReadCommandSocketFailed{};
        }
        int* p = reinterpret_cast<int*>(CMSG_DATA(cmsghdr));
        cmd.segfd = *p;
        cmd.sndfd = *(p + 1);
        cmd.rcvfd = *(p + 2);
        return cmd;
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
            throw CreatingSocketPairFailed{};
        }
    }

    /**
     * Fork the server process, and set some related variables.
     */
    void
    StartServer()
    {
#ifdef PROXY_DEBUG
        PROXY_LOG(DBG) << "About to fork()";
#endif
        pid_t pid = fork();
        if (pid == 0) {
            // Child (Server)
            side_ = kChild;
#if defined(__FreeBSD__) && defined(Proxy_CapabilityMode)
	    cap_enter();
#endif
            ActivateLiveCheck();
        } else if (pid > 0) {
            // Parent (Client)
            side_ = kParent;
            child_pid_ = pid;
        } else {
            PROXY_LOG(ERR) << "fork() failed: ";
            throw ForkFailed{};
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
    ActivateLiveCheck() const noexcept
    {
        InstallLiveCheckSignalHandlers();
        StartLiveCheckSignalTimer();
    }

    /**
     * Create a POSIX timer to send a SIGALRM regularly.
     */
    void
    StartLiveCheckSignalTimer() const noexcept
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
    InstallLiveCheckSignalHandlers() const
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
        explicit Execution(PRX* proxy) noexcept
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
#ifdef PROXY_DEBUG
                PROXY_LOG(DBG) << "+ Creating new segment descriptor." << std::endl;
                PROXY_LOG(DBG) << "+ New segment descriptor" << std::endl;
#endif
                segd_ = proxy_->OpenChannel(kParent);
                stub_ = new Stub<SZ>(*segd_);
                auto service_func =
                    &AbstractProxyWorkLoopWrapper<decltype(proxy_), SZ, RET, Args...>;
                proxy_->SendNewChannelInfo(segd_->GetSegFd(),
                                           segd_->GetSndFd(),
                                           segd_->GetRcvFd(),
                                           service_func);
            } else {
#ifdef PROXY_DEBUG
                PROXY_LOG(DBG) << "Reusing existing segment descriptor." << std::endl;
#endif
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
        Shutdown() const
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
        ~Execution() noexcept
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

    uint64_t
    GenerateExecutionId() const noexcept
    {
        return rand();
    }

    template <typename RET, typename... Args>
    RET
    ExecuteInternal(Selector sel, Args... args)
    {
        using EXETYPE = Execution<AbstractProxy<SUB, SZ>, RET, Args...>;
        using EXEMAPTYPE = std::map<void*, std::any>;
        static bool first_run = true;
        static uint64_t unique_id = GenerateExecutionId();
        if (first_run) {
            first_run = false;
            static EXEMAPTYPE* executions = new EXEMAPTYPE{};
            all_executions.insert({unique_id, executions});
        }
        auto executions = std::any_cast<EXEMAPTYPE*>(
                                    std::get<1>(*(all_executions.find(unique_id))));
        EXETYPE* execution = nullptr;
        auto iter = executions->find(this);
        if (iter == executions->end()) {
            if (sel == kQuery) {
                execution = new EXETYPE{this};
                executions->insert({this, execution});
            } else
                throw TriedToStopNonExistentSegmentDescriptor{};
        } else {
            execution = std::any_cast<EXETYPE*>(std::get<1>(*iter));
            if (sel == kStop) {
#ifdef PROXY_DEBUG
                PROXY_LOG(DBG) << "Parent: Got kStop command for Execution instance";
#endif
                executions->erase(iter);
#ifdef PROXY_DEBUG
                PROXY_LOG(DBG) << "executions count: " << executions->size() << std::endl;
#endif
                delete execution;
                return RET{};
            } else if (sel == kShutDown) {
#ifdef PROXY_DEBUG
                PROXY_LOG(DBG) << "Parent: Got kShutDown command for Execution instance";
#endif
                executions->erase(iter);
                for (auto& e : *executions)
                    delete std::any_cast<EXETYPE*>(std::get<1>(e));
                executions->clear();
                execution->Shutdown();
                delete execution;
                return RET{};
            }
        }
        if (sel == kQuery) {
            try {
                return execution->_(args...);
            } catch (...) {
                auto iter = executions->find(this);
                executions->erase(iter);
                execution->Shutdown();
                delete execution;
                throw;
            }
        }
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
        /**
         * Compile-time check to ensure that the selected buffer size SZ is
         * sufficient for the provided argument and return types.
         */
        if constexpr (sizeof...(Args) > 0)
            static_assert(CalcBufSize<Args...>() <= SZ  , "SZ is too small for Args");
        static_assert(CalcBufSize<RET>() <= SZ      , "SZ is too small for RET");

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
    /**
     * A file descriptor to the DSO file. This will be used to load the
     * DSO via fdlopen()
     */
#if defined(__FreeBSD__) && defined(Proxy_CapabilityMode)
    int sofd_;
#endif

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
    inline static std::unordered_map<uint64_t, std::any> all_executions{};
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
    explicit ProxySO(std::string soname)
        : detail::AbstractProxy<ProxySO, SZ>{soname}
    {
        using namespace detail;
#ifdef PROXY_DEBUG
        PROXY_LOG(DBG) << "Going to dlopen '" << soname << "'" << std::endl;
#endif
        if (this->side_ == kChild) {
#if defined(__FreeBSD__) && defined(Proxy_CapabilityMode)
            handle_ = fdlopen(this->sofd_, RTLD_LOCAL | RTLD_NOW);
#else
            handle_ = dlopen(soname.c_str(), RTLD_LOCAL | RTLD_NOW);
#endif
            if (!handle_) {
#ifdef PROXY_DEBUG
                PROXY_LOG(ERR) << "Failed to open DSO: " << dlerror() << std::endl;
#endif
                exit(EC_Opening_DSO_Failed);
            }
        }
#if defined(__FreeBSD__) && defined(Proxy_CapabilityMode)
        PXNOINT(close(this->sofd_));
#endif
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
#ifdef PROXY_DEBUG
            PROXY_LOG(DBG) << "DSO function cache miss: ("
                           << func_name.c_str() << ")" << std::endl;
#endif
            func_ptr = (func_type)dlsym(handle_, func_name.c_str());
            funcs_[func_name] = reinterpret_cast<void*>(func_ptr);
            if (!func_ptr) {
                PROXY_LOG(ERR) << "Failed to lookup function in DSO" << std::endl;
                PROXY_LOG(ERR) << "dlerror: " << dlerror() << std::endl;
                throw DSOFunctionLookupFailed{};
            }
        } else {
#ifdef PROXY_DEBUG
            PROXY_LOG(DBG) << "DSO function cache hit: ("
                           << func_name.c_str() << ")" << std::endl;
#endif
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
    void* handle_ = nullptr;
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
 * child. Had I used the constructors of these classes directly, I would have
 * had to block the child in its constructor, which may be problematic.
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
        auto proxy {ProxyDirect<SZ, SERV>{}};
        proxy.BlockChildOnCommandLoop();
        // Unreachable in server (child) process
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
        auto proxy {ProxySO<SZ>{dso_path}};
        proxy.BlockChildOnCommandLoop();
        // Unreachable in server (child) process
        return proxy;
    }

};

}
