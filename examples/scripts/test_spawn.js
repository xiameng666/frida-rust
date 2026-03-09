// test_spawn.js — spawn 模式测试脚本
// 用法: cargo run -p agent-host -- --spawn examples/scripts/test_spawn.js

var dlopen = Module.findExportByName("libdl.so", "android_dlopen_ext");
if (dlopen) {
    Interceptor.attach(dlopen, {
        onEnter: function(args) {
            var path = Memory.readCString(args[0]);
            console.log("[dlopen] loading: " + path);
        },
        onLeave: function(retval) {
            console.log("[dlopen] result: " + retval);
        }
    });
    console.log("[+] hooked android_dlopen_ext at " + dlopen);
} else {
    console.log("[-] android_dlopen_ext not found");
}

console.log("[+] spawn hook ready, waiting for resume...");
