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

class Service {
public:
#define _(n)    std::get<n>(tup)
#define _res   _(0)

    std::string
    Handle(std::tuple<>& tup) {
        return std::string{"test result"};
    }

    double
    Handle(std::tuple<int, int, int>& tup) {
        auto res = _(0) + _(1) + _(2) + .78;
        return res;
    }

    std::size_t
    Handle(std::tuple<int, std::string>& tup) {
        auto res = _(0) + _(1).size();
        return res;
    }

    std::string
    Handle(std::tuple<std::string>& tup) {
        auto res = "return:" + _(0);
        return res;
    }

    int
    Handle(std::tuple<int>& tup) {
        auto res = 1 + _(0);
        return res;
    }

    double
    Handle(std::tuple<int, int>& tup) {
        auto res = _(0) + _(1) + 0.1;
        return res;
    }

    float
    Handle(std::tuple<int, int, int, int, int, float, int, int, float,
                      int, int, double, int, int, int>& tup) {
        auto res = _(0) + _(1) + _(2) + _(3) + _(4) + _(5) + _(6) + _(7) +
                   _(8) + _(9) + _(10) + _(11) + _(12) + _(13) + _(14) + 0.5;
        return res;
    }

    float
    Handle(std::tuple<int, float, int, int, int, int, int, float, int, int,
                      float, int, int, double, int, int, int>& tup) {
        auto res = _(0) + _(1) + _(2) + _(3) + _(4) + _(5) + _(6) + _(7) +
                   _(8) + _(9) + _(10) + _(11) + _(12) + _(13) + _(14) +
                   _(15) + _(16) + 0.5f;
        return res;
    }

    std::string
    Handle(std::tuple<std::string, uint64_t>& tup) {
        constexpr int S = 4096;
        char* largestr = new char[S + 1];
        for (std::size_t s = 0; s < S + 1; s++)
            largestr[s] = 'X';
        largestr[S] = 0;
        return std::string{largestr};
    }
#undef _
#undef _res
};

using namespace capsiproxy;

TEST(ProxyTest, NoArgs) {
    auto p = Proxy<4096, Service>::Build();
    auto result = p.Execute<std::string>();
    ASSERT_STREQ(result.c_str(), "test result");
    p.Shutdown<std::string>();
}

TEST(ProxyTest, TwoNumericBack2Back) {
    auto p = Proxy<4096, Service>::Build();
    auto result = p.Execute<int>(16);
    ASSERT_EQ(result, 17);
    auto result2 = p.Execute<double>(7, 19, 23);
    ASSERT_EQ(result2, 49.78);
    p.Shutdown<double>(0, 0, 0);
}

TEST(ProxyTest, ThreeNumericBack2BackSameTypeAsOldObject) {
    auto p = Proxy<4096, Service>::Build();
    auto result = p.Execute<double>(1, 10, 34);
    ASSERT_EQ(result, 45.78);
    auto result2 = p.Execute<double>(123, 9);
    ASSERT_EQ(result2, 132.1);
    result = p.Execute<double>(17, 29, 33);
    ASSERT_EQ(result, 79.78);
    p.Shutdown<double>(0, 0, 0);
}

TEST(ProxyTest, LargeNumberOfArgs) {
    auto p = Proxy<4096, Service>::Build();
    auto result = p.Execute<float>(4, 3, 1, 4, 5, 2.2f, 111, 93, 1.23f, 12,
                                   99, 1.2323, 2, 8, 11);
    ASSERT_EQ(result, 358.1623f);
    p.Shutdown<float>(0, 0, 0, 0, 0, 0.0f, 0, 0, 0.0f, 0, 0, 0.0, 0, 0, 0);
}

#if defined(STATIC_TESTS)
/**
 * The following test should not compile, since it tries to instantiate a proxy
 * with more than 16 arguments!
 */
TEST(ProxyTest, TooManyArgs) {
    auto p = Proxy<4096, Service>::Build();
    auto result = p.Execute<float>(10, 1.1f, 4, 3, 1, 4, 5, 2.2f, 111, 93,
                                   1.23f, 12, 99, 1.2323, 2, 8, 11);
    ASSERT_EQ(result, 358.1623f);
}
#endif

TEST(ProxyTest, SimpleString) {
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
}

TEST(ProxyTest, TooLargeResponseStringForSZ) {
    auto p = Proxy<4096, Service>::Build();
    EXPECT_ANY_THROW(p.Execute<std::string>("dummy"s, UINT64_MAX));
}

TEST(ProxyTest, TwoStringBack2BackStringReturn) {
    auto p = Proxy<4096, Service>::Build();
    auto result = p.Execute<std::string>("hello_2"s);
    ASSERT_STREQ(result.c_str(), "return:hello_2");
    p.Stop<std::string>(""s);
    auto result2 = p.Execute<std::string>("hello_3"s);
    ASSERT_STREQ(result2.c_str(), "return:hello_3");
}

TEST(ProxyTest, EmptyString) {
    auto p = Proxy<4096, Service>::Build();
    auto result = p.Execute<std::string>(""s);
    ASSERT_STREQ(result.c_str(), "return:");
}

TEST(ProxyTest, TwoProxiesStringBack2BackStringReturn) {
    auto p1 = Proxy<4096, Service>::Build();
    auto p2 = Proxy<4096, Service>::Build();
    auto result = p1.Execute<std::string>("hello_X"s);
    ASSERT_STREQ(result.c_str(), "return:hello_X");
    p1.Stop<std::string>(""s);

    auto result2 = p2.Execute<std::string>("hello_Y"s);
    ASSERT_STREQ(result2.c_str(), "return:hello_Y");
    p2.Shutdown<std::string>(""s);
}

TEST(ProxyDLOAPITest, TwoNumericBack2Back) {
    auto p = Proxy<4096>::Build("./libtest.so");
    auto result = p.Execute<int>("add"s, 20, 30);
    ASSERT_EQ(result, 50);
    result = p.Execute<int>("add"s, 163, 9);
    ASSERT_EQ(result, 172);
    p.Shutdown<int>(""s, 0, 0);
}

TEST(ProxyDLOAPITest, NonExistantDso) {
    auto p = Proxy<4096>::Build("./libnotexists.so");
    EXPECT_THROW(p.Execute<int>("add"s, 20, 30),
                 capsiproxy::ChildTerminated);

}

}
