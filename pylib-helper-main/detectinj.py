import psutil
import time



# now this code is modified scanmodules.py but with a difference, in this code, it scans for new modules
# that are added to your target process, for example injecting your dll, it will refresh its list and tell
# us if something new was added, for example your dll. this can help with stealth mode injection and making your
# exploit undetected. 




def get_modules_from_process(target_executable):
    initial_modules = set()

    # Obtain the initial set of modules
    for process in psutil.process_iter(['pid', 'name', 'memory_info', 'exe']):
        if process.info['exe'] and target_executable in process.info['exe']:
            try:
                for module in psutil.Process(process.info['pid']).memory_maps(grouped=True):
                    initial_modules.add(module)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                print(f"Error accessing information for PID {process.info['pid']}")

    while True:
        for process in psutil.process_iter(['pid', 'name', 'memory_info', 'exe']):
            if process.info['exe'] and target_executable in process.info['exe']:
                print(f"Modules for {target_executable} (PID {process.info['pid']}):")
                try:
                    current_modules = set()
                    for module in psutil.Process(process.info['pid']).memory_maps(grouped=True):
                        current_modules.add(module)
                        print(f"  {module}")




                    # Check for injected modules
                    if current_modules != initial_modules:
                        print("Warning: Detected injected modules!")

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    print(f"Error accessing information for PID {process.info['pid']}")
        
        time.sleep(5)

if __name__ == "__main__":
    target_executable = "Windows10Universal.exe" # change to process of choice.
    get_modules_from_process(target_executable)
