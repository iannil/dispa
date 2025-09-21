#![no_std]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

// Minimal allocator interface for host
#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    unsafe {
        let layout = core::alloc::Layout::from_size_align_unchecked(size as usize, 1);
        let ptr = alloc::alloc::alloc(layout);
        ptr as i32
    }
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: i32, size: i32) {
    unsafe {
        let layout = core::alloc::Layout::from_size_align_unchecked(size as usize, 1);
        alloc::alloc::dealloc(ptr as *mut u8, layout);
    }
}

static LAST_LEN: AtomicI32 = AtomicI32::new(0);

fn set_output_json(s: &str) -> i32 {
    let bytes = s.as_bytes();
    let out_ptr = alloc(bytes.len() as i32);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr as *mut u8, bytes.len());
    }
    LAST_LEN.store(bytes.len() as i32, Ordering::SeqCst);
    out_ptr
}

fn handle(stage: &str, _ptr: i32, _len: i32) -> i32 {
    let json = match stage {
        "request" => "{\"set_headers\":{\"x-wasm-rust\":\"1\"}}",
        _ => "{\"set_headers\":{\"x-wasm-rust\":\"1\"}}",
    };
    set_output_json(json)
}

#[no_mangle]
pub extern "C" fn dispa_on_request(ptr: i32, len: i32) -> i32 {
    handle("request", ptr, len)
}

#[no_mangle]
pub extern "C" fn dispa_on_response(ptr: i32, len: i32) -> i32 {
    handle("response", ptr, len)
}

#[no_mangle]
pub extern "C" fn dispa_get_result_len() -> i32 { LAST_LEN.load(Ordering::SeqCst) }

// Provide the required lang items for no_std (panic handler)
use core::panic::PanicInfo;
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

