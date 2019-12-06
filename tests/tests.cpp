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

using Req1 = std::tuple<double, int, int, int>;
using Req2 = std::tuple<std::size_t, std::string>;
using Req3 = std::tuple<std::string, std::string>;
using Req4 = std::tuple<int, std::string, int, int>;

template <typename T>
class Service {
public:
    using request_type = T;
// XXX: use user defined literals instead of this macro
#define _(n)    std::get<n>(tup)
#define _res   _(0)

    Service() {

    }

    void
    Handle(Req1& tup) {
        _res = _(1) + _(2) + _(3) + .78;
    }

    void
    Handle(Req2& tup) {
        _res = _(1).size();
    }

    void
    Handle(Req3& tup) {
        _res = "return:" + _(1);
    }

#undef _
#undef _res
};

TEST(ProxyTest, NumericTest) {
    auto p = Proxy<Req1, 4096, Service>::Build();
    auto result = p.Execute(1, 10, 34);
    ASSERT_EQ(result, 45.78);
    result = p.Execute(7, 19, 23);
    ASSERT_EQ(result, 49.78);
}

TEST(ProxyTest, StringTest) {
    auto p = Proxy<Req2, 4096, Service>::Build();
    auto result = p.Execute("hello"s);
    ASSERT_EQ(result, 5);
}

TEST(ProxyTest, StringReturnTest) {
    auto p = Proxy<Req3, 4096, Service>::Build();
    auto result = p.Execute("hello_2"s);
    ASSERT_STREQ(result.c_str(), "return:hello_2");
}

TEST(ProxyDLOAPITest, NumericTest) {
    auto p = Proxy<Req4, 4096>::Build("/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/libtest.so");
    auto result = p.Execute("add"s, 20, 30);
    ASSERT_EQ(result, 50);
}

}
