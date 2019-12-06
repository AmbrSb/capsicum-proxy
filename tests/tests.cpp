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

template<typename T>
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

#undef _
#undef _res
};

TEST(ProxyTest, NumericTest) {
    auto p = Proxy<Req1, Ret1, 4096, Service>::Build();
    auto result = p.Execute(1, 10, 34);
    ASSERT_EQ(result, 45.78);
    result = p.Execute(7, 19, 23);
    ASSERT_EQ(result, 49.78);
}

TEST(ProxyTest, StringTest) {
    auto p = Proxy<Req2, Ret2, 4096, Service>::Build();
    auto result = p.Execute(9, "hello"s);
    ASSERT_EQ(result, 14);
}

TEST(ProxyTest, StringReturnTest) {
    auto p = Proxy<Req3, Ret3, 4096, Service>::Build();
    auto result = p.Execute("hello_2"s);
    ASSERT_STREQ(result.c_str(), "return:hello_2");
}

TEST(ProxyDLOAPITest, NumericTest) {
    auto p = Proxy<Req4, Ret4, 4096>::Build("/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/libtest.so");
    auto result = p.Execute("add"s, 20, 30);
    ASSERT_EQ(result, 50);
}

}
