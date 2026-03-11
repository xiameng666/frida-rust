//! wxshadow 隐藏断点 API
//!
//! 通过 prctl 系统调用与内核中的 wxshadow KPM 模块通信。
//! wxshadow 使用 W^X 影子页实现对 CRC32 校验不可见的断点。
//!
//! # 用法
//! ```ignore
//! wx_hook(pid, addr, WxAction::Log)?;            // 观测断点
//! wx_hook(pid, addr, WxAction::Arg(0, 1))?;      // 修改第1个参数为1
//! wx_hook(pid, addr, WxAction::Ret(0))?;          // 修改返回值为0
//! wx_unhook(pid, addr)?;                          // 删除断点
//! ```

/// prctl option codes (wxshadow 自定义, "WX" 的 ASCII 前缀)
const WX_SET_BP: libc::c_int = 0x57585801;
const WX_SET_REG: libc::c_int = 0x57585802;
const WX_DEL_BP: libc::c_int = 0x57585803;

/// 断点动作
#[derive(Debug, Clone)]
pub enum WxAction {
    /// 仅观测 — 命中时在 dmesg 打印寄存器快照
    Log,
    /// 修改参数 (参数索引 0-7 → x0-x7, 值)
    Arg(u8, u64),
    /// 修改返回值 (x0) — 断点需设在 ret 指令处
    Ret(u64),
    /// 修改多个寄存器 [(寄存器号, 值), ...]
    Regs(Vec<(u8, u64)>),
}

/// 设置 wxshadow 隐藏断点。
///
/// `pid`: 目标进程 PID (0 = 当前进程)
/// `addr`: 断点地址 (必须 4 字节对齐)
/// `action`: 命中时的行为
pub fn wx_hook(pid: u32, addr: u64, action: WxAction) -> Result<(), String> {
    // 1. 设置断点
    let ret = unsafe {
        libc::prctl(
            WX_SET_BP,
            pid as libc::c_ulong,
            addr as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if ret < 0 {
        return Err(format!(
            "SET_BP 0x{:x}: {}",
            addr,
            std::io::Error::last_os_error()
        ));
    }

    // 2. 配置寄存器修改
    match action {
        WxAction::Log => {}
        WxAction::Arg(idx, val) => {
            if idx > 7 {
                return Err(format!("arg index must be 0-7, got {idx}"));
            }
            set_reg(pid, addr, idx, val)?;
        }
        WxAction::Ret(val) => {
            set_reg(pid, addr, 0, val)?;
        }
        WxAction::Regs(ref mods) => {
            for &(reg, val) in mods {
                set_reg(pid, addr, reg, val)?;
            }
        }
    }

    Ok(())
}

/// 删除 wxshadow 断点。
pub fn wx_unhook(pid: u32, addr: u64) -> Result<(), String> {
    let ret = unsafe {
        libc::prctl(
            WX_DEL_BP,
            pid as libc::c_ulong,
            addr as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if ret < 0 {
        return Err(format!(
            "DEL_BP 0x{:x}: {}",
            addr,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// 设置单个寄存器修改规则。
fn set_reg(pid: u32, addr: u64, reg: u8, val: u64) -> Result<(), String> {
    let ret = unsafe {
        libc::prctl(
            WX_SET_REG,
            pid as libc::c_ulong,
            addr as libc::c_ulong,
            reg as libc::c_ulong,
            val as libc::c_ulong,
        )
    };
    if ret < 0 {
        return Err(format!(
            "SET_REG x{}=0x{:x}: {}",
            reg,
            val,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
