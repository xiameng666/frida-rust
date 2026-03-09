// test_nohook.js — 最简测试，不装任何 hook
// 验证 jsinit + loadjs + resume 流程正常

console.log("[+] script loaded, pid = " + Process.id);
console.log("[+] arch = " + Process.arch);
console.log("[+] no hooks installed, just testing spawn flow");
