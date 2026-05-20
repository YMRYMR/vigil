#![cfg(windows)]

use std::ffi::c_void;
use std::sync::OnceLock;
use windows::core::{w, GUID, PCSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, HMODULE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_DISPLAY_DATA0, FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SUBLAYER0,
};
use windows::Win32::System::LibraryLoader::{FreeLibrary, GetProcAddress, LoadLibraryW};

const FWP_E_ALREADY_EXISTS_STATUS: u32 = 0x8032_0009;
const VIGIL_WFP_PROVIDER_KEY: GUID = GUID::from_u128(0x3b6f3d34_6150_4e3c_9169_7df0c5f1cb52);
const VIGIL_WFP_SUBLAYER_KEY: GUID = GUID::from_u128(0xe7fae0d0_3af1_4b9f_88ea_ee11e08c9c4a);
const VIGIL_WFP_SUBLAYER_WEIGHT: u16 = 0x7000;

type FwpmEngineOpen0Fn = unsafe extern "system" fn(
    server_name: PCWSTR,
    authn_service: u32,
    auth_identity: *const c_void,
    session: *const FWPM_SESSION0,
    engine_handle: *mut HANDLE,
) -> u32;
type FwpmEngineClose0Fn = unsafe extern "system" fn(engine_handle: HANDLE) -> u32;
type FwpmProviderAdd0Fn = unsafe extern "system" fn(
    engine_handle: HANDLE,
    provider: *const FWPM_PROVIDER0,
    sd: *const c_void,
) -> u32;
type FwpmSubLayerAdd0Fn = unsafe extern "system" fn(
    engine_handle: HANDLE,
    sub_layer: *const FWPM_SUBLAYER0,
    sd: *const c_void,
) -> u32;

static FOUNDATION_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

pub fn ensure_foundation() -> Result<(), String> {
    FOUNDATION_RESULT.get_or_init(bootstrap_foundation).clone()
}

fn bootstrap_foundation() -> Result<(), String> {
    let api = unsafe { WfpApi::load()? };
    let session = api.open_engine()?;
    session.ensure_provider()?;
    session.ensure_sublayer()?;
    Ok(())
}

struct WfpApi {
    module: HMODULE,
    engine_open: FwpmEngineOpen0Fn,
    engine_close: FwpmEngineClose0Fn,
    provider_add: FwpmProviderAdd0Fn,
    sublayer_add: FwpmSubLayerAdd0Fn,
}

impl WfpApi {
    unsafe fn load() -> Result<Self, String> {
        let module = LoadLibraryW(w!("Fwpuclnt.dll"))
            .map_err(|err| format!("load Fwpuclnt.dll: {err}"))?;
        Ok(Self {
            module,
            engine_open: load_symbol(module, b"FwpmEngineOpen0\0")?,
            engine_close: load_symbol(module, b"FwpmEngineClose0\0")?,
            provider_add: load_symbol(module, b"FwpmProviderAdd0\0")?,
            sublayer_add: load_symbol(module, b"FwpmSubLayerAdd0\0")?,
        })
    }

    fn open_engine(&self) -> Result<WfpSession<'_>, String> {
        let session = FWPM_SESSION0::default();
        let mut handle = HANDLE::default();
        let status = unsafe {
            (self.engine_open)(PCWSTR::null(), 0, std::ptr::null(), &session, &mut handle)
        };
        if status != 0 {
            return Err(format!(
                "open WFP engine session failed with 0x{status:08x}"
            ));
        }
        Ok(WfpSession { api: self, handle })
    }
}

impl Drop for WfpApi {
    fn drop(&mut self) {
        unsafe {
            if self.module.0 != 0 {
                let _ = FreeLibrary(self.module);
            }
        }
    }
}

struct WfpSession<'a> {
    api: &'a WfpApi,
    handle: HANDLE,
}

impl WfpSession<'_> {
    fn ensure_provider(&self) -> Result<(), String> {
        let mut name = wide("Vigil");
        let mut description = wide("Vigil native firewall engine");
        let mut provider = FWPM_PROVIDER0::default();
        provider.providerKey = VIGIL_WFP_PROVIDER_KEY;
        provider.displayData = FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            description: PWSTR(description.as_mut_ptr()),
        };
        let status = unsafe { (self.api.provider_add)(self.handle, &provider, std::ptr::null()) };
        ok_or_already_exists(status, "register WFP provider")
    }

    fn ensure_sublayer(&self) -> Result<(), String> {
        let mut name = wide("Vigil dynamic firewall");
        let mut description = wide("Vigil-owned transient and boot-healed filters");
        let mut sublayer = FWPM_SUBLAYER0::default();
        sublayer.subLayerKey = VIGIL_WFP_SUBLAYER_KEY;
        sublayer.displayData = FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            description: PWSTR(description.as_mut_ptr()),
        };
        sublayer.providerKey = std::ptr::addr_of!(VIGIL_WFP_PROVIDER_KEY) as _;
        sublayer.weight = VIGIL_WFP_SUBLAYER_WEIGHT;
        let status = unsafe { (self.api.sublayer_add)(self.handle, &sublayer, std::ptr::null()) };
        ok_or_already_exists(status, "register WFP sublayer")
    }
}

impl Drop for WfpSession<'_> {
    fn drop(&mut self) {
        unsafe {
            let _ = (self.api.engine_close)(self.handle);
        }
    }
}

unsafe fn load_symbol<T: Copy>(module: HMODULE, name: &'static [u8]) -> Result<T, String> {
    let proc = GetProcAddress(module, PCSTR(name.as_ptr()));
    let Some(proc) = proc else {
        let symbol = String::from_utf8_lossy(&name[..name.len().saturating_sub(1)]).into_owned();
        return Err(format!("resolve {symbol} from Fwpuclnt.dll"));
    };
    Ok(std::mem::transmute_copy(&proc))
}

fn ok_or_already_exists(status: u32, action: &str) -> Result<(), String> {
    if status == 0 || status == FWP_E_ALREADY_EXISTS_STATUS {
        Ok(())
    } else {
        Err(format!("{action} failed with 0x{status:08x}"))
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
