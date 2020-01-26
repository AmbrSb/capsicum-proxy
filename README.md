# CapsyProxy
Using this single-header library you can easily run any untrusted piece of code, or a function in an untrusted dynamic shared object, inside a capsicum-based sandbox, in a separate process with minimum privileges.
All fast-path communication between the client code and the sandbox are done via shared memory segments to minimize latency and avoid system call and context switching overhead.
All similar requests can be run in a single sandbox to avoid the overhead of process creation and setup.

# Example
## Sandboxing a DSO
Assume we have a library libtest.so that has a function named 'add' that takes two integers and returns the sum. You can sandbox the DSO as easily as:
```C++
    auto p = Proxy<4096>::Build("./libtest.so");
    auto result = p.Execute<int>("add"s, 20, 30);
```
## Sandboxing part of the source code
You should create a class that has a method named 'Handle' with appropriate signature.
```c++
    class Service {
    public:
        std::string
        Handle(std::tuple<std::string>& tup) {
            /**
             * Use the untrusted code here.
             * Anything in this method will run in a separate sandboxed process.
             */
        }
    };
```
Then sandbox it as this:
```C++
    auto p = Proxy<4096, Service>::Build();
    auto result = p.Execute<std::string>("echo request"s);
```
See `test.cpp` for more examples.

The sandbox will keep running waiting for more requests from the client code. You can explicitly ask it to stop:
```C++
    p.Shutdown<std::string>(""s);
```
Or to just close a single channel of a specific type, without closing down the whole sandbox:
```C++
    p.Stop<std::string>(""s);
```
In the latter case you can continue to send requests to the sandbox for other types of requests.

Each instance of proxy class will create a single sandboxed process. One can create as many instances as necessary.

