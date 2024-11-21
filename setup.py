from cx_Freeze import setup, Executable

# Define the executable and options
executables = [Executable("ExelaV2StealerDecompiler.py", target_name="ExelaV2StealerDecompiler.exe", 
                          base="Win32GUI", 
                          icon=None,  # You can add an icon if you have one
                          uac_admin=1)]  # This line requests admin privileges

# Dependencies are automatically detected, but you can fine-tune them here
build_options = {
    "packages": [],  # Add any Python packages used in your script
    "includes": [],  # Add any modules your script explicitly needs
    "excludes": ["tkinter"],  # Exclude unnecessary modules
    "include_files": [],  # Include additional files if needed
}

setup(
    name="Roflz",
    version="1.0",
    description="ExelaV2Decompiler",
    options={"build_exe": build_options},
    executables=executables,
)
