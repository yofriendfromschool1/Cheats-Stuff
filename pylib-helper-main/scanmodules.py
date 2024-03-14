import psutil
import time



# now this version of code is modified scanmodules.py but with injection scanning, so if something
# has been injected in your target process, it detects it. this can help with stealth mode injection
# and making your exploit undetected from roblox reading it.



def get_modules_from_process(target_executable):
    while True:
        # Get the initial list of modules
        initial_modules = set()
        for process in psutil.process_iter(['pid', 'name', 'memory_info', 'exe']):
            if process.info['exe'] and target_executable in process.info['exe']:
                try:
                    for module in psutil.Process(process.info['pid']).memory_maps(grouped=True):
                        initial_modules.add(module)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    print(f"Error accessing information for PID {process.info['pid']}")

        
        time.sleep(5)


        # Getting updated list of modules
        updated_modules = set()
        for process in psutil.process_iter(['pid', 'name', 'memory_info', 'exe']):
            if process.info['exe'] and target_executable in process.info['exe']:
                try:
                    for module in psutil.Process(process.info['pid']).memory_maps(grouped=True):
                        updated_modules.add(module)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    print(f"Error accessing information for PID {process.info['pid']}")



        # Compare the initial and updated modules etc etc.
        new_modules = updated_modules - initial_modules
        removed_modules = initial_modules - updated_modules

        if new_modules or removed_modules:
            print(f"Modules for {target_executable} (PID {process.info['pid']}):")
            if new_modules:
                print("New Modules:")
                for module in new_modules:
                    print(f"  {module}")
            if removed_modules:
                print("Removed Modules:")
                for module in removed_modules:
                    print(f"  {module}")

if __name__ == "__main__":
    target_executable = "Windows10Universal.exe"
    get_modules_from_process(target_executable)
