#include <map>
#include <tuple>
#include <type_traits>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>

#include <gtest/gtest.h>
#include <proxy.hpp>


using ::testing::EmptyTestEventListener;
using ::testing::InitGoogleTest;
using ::testing::Test;
using ::testing::TestEventListeners;
using ::testing::TestInfo;
using ::testing::TestPartResult;
using ::testing::UnitTest;

namespace {

using namespace std::literals;

using Req1 = std::tuple<int, int, int>;
using Ret1 = double;

using Req2 = std::tuple<int, std::string>;
using Ret2 = std::size_t;

using Req3 = std::tuple<std::string>;
using Ret3 = std::string;

using Req4 = std::tuple<std::string, int, int>;
using Ret4 = int;

using Req5 = std::tuple<int>;
using Ret5 = int;


class Service {
public:
// XXX: use user defined literals instead of this macro
#define _(n)    std::get<n>(tup)
#define _res   _(0)

    Service() {

    }

    Ret1
    Handle(Req1& tup) {
        auto res = _(0) + _(1) + _(2) + .78;
        return res;
    }

    Ret2
    Handle(Req2& tup) {
        auto res = _(0) + _(1).size();
        return res;
    }

    Ret3
    Handle(Req3& tup) {
        auto res = "return:" + _(0);
        return res;
    }

    Ret5
    Handle(Req5& tup) {
        auto res = 1 + _(0);
        return res;
    }

#undef _
#undef _res
};

using namespace capsiproxy;

TEST(ProxyTest, NumericTest) {
    auto p = Proxy<4096, Service>::Build();
    auto result = p.Execute<int>(16);
    ASSERT_EQ(result, 17);
    auto result2 = p.Execute<double>(7, 19, 23);
    ASSERT_EQ(result2, 49.78);
    p.Shutdown<double>(0, 0, 0);
}

TEST(ProxyTest, NumericTest2) {
    auto p = Proxy<4096, Service>::Build();
    auto result = p.Execute<double>(1, 10, 34);
    ASSERT_EQ(result, 45.78);
    result = p.Execute<double>(17, 29, 33);
    ASSERT_EQ(result, 79.78);
    p.Shutdown<double>(0, 0, 0);
}

TEST(ProxyTest, StringTest) {
    auto p = Proxy<4096, Service>::Build();
    auto result = p.Execute<std::size_t>(9, "hello"s);
    ASSERT_EQ(result, 14);
    p.Shutdown<std::size_t>(0, ""s);
}

TEST(ProxyTest, OperationAfterShutdownShouldThrow) {
    auto p = Proxy<4096, Service>::Build();
    auto result = p.Execute<std::size_t>(9, "hello"s);
    ASSERT_EQ(result, 14);
    p.Shutdown<std::size_t>(0, ""s);
    EXPECT_THROW(p.Execute<std::size_t>(1, "a"s),
                 capsiproxy::InvalidProxyState);
    EXPECT_THROW(p.Shutdown<std::size_t>(1, "a"s),
                 capsiproxy::InvalidProxyState);
    EXPECT_THROW(p.Stop<std::size_t>(1, "a"s),
                 capsiproxy::InvalidProxyState);
}

TEST(ProxyTest, TooLargeStringParametersForSZ) {
    auto p = Proxy<4096, Service>::Build();
    constexpr int S = 5000;
    char* largestr = new char[S];
    for (std::size_t s = 0; s < S; s++)
        largestr[s] = 'a';
    largestr[S - 1] = 0;
    EXPECT_THROW(p.Execute<std::string>(std::string{largestr}),
                 capsiproxy::SendBufferOverflow);
    p.Stop<std::string>(""s);
}

TEST(ProxyTest, StringReturnTest) {
    auto p = Proxy<4096, Service>::Build();
    auto result = p.Execute<std::string>("hello_2"s);
    ASSERT_STREQ(result.c_str(), "return:hello_2");
    p.Stop<std::string>(""s);
    auto result2 = p.Execute<std::string>("hello_3"s);
    ASSERT_STREQ(result2.c_str(), "return:hello_3");
}

TEST(ProxyDLOAPITest, NumericTest) {
    auto p = Proxy<4096>::Build("/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/libtest.so");
    auto result = p.Execute<int>("add"s, 20, 30);
    ASSERT_EQ(result, 50);
    result = p.Execute<int>("add"s, 163, 9);
    ASSERT_EQ(result, 172);
    p.Shutdown<int>(""s, 0, 0);
}

}
