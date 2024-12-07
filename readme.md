# Windows Hardening PowerShell Script

## Overview

This is a script designed to implement common-sense hardening features & policies to create a more secure and safer environment. Users can select from three execution modes—`auto`, `ask`, and `verify`, to configure and inspect the health of their system. In "ask" mode, the script will present the benefits and drawbacks of a proposed setting, allowing the user to decide whether or not it's enablement is right for them prior to implementing.

---

## Key Features

### **1. System Configuration Tasks**
- Configures critical system settings such as enabling BitLocker, enhancing PowerShell logging, and optimizing DNS configurations.

### **2. Security Policies Hardening**
- Implements policies like Attack Surface Reduction (ASR) rules, UAC enhancements, and disabling legacy protocols (e.g., SMBv1, Telnet).

### **3. Application Hardening**
- Strengthens browser security for Google Chrome and Microsoft Edge by enabling features such as HTTPS-only mode, blocking third-party cookies, and enforcing automatic updates.

### **4. System Hardening**
- Disables unnecessary services, enhances log retention policies, and secures time synchronization.

---

## System Requirements

- **Operating System**: Windows 10, Windows 11, or Windows Server 2016/2019/2022.
- **Permissions**: Must be executed with administrative privileges.
- **PowerShell Version**: PowerShell 5.1 or later.

---

## Running the Script

### **Step 1: Download the Script**
Save the script file (e.g., `harden.ps1`) to a known location, such as `C:\Scripts`.

### **Step 2: Open PowerShell as Administrator**
- Search for **PowerShell** in the Start menu.
- Right-click on **Windows PowerShell** and choose **Run as Administrator**.

### **Step 3: Set Execution Policy**
Allow script execution by temporarily bypassing the PowerShell execution policy for this session:
```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### **Step 4: Navigate to the Script Directory**
Change to the directory where the script is located:
```
cd C:\Scripts
```

### **Step 5: Run the Script**
Execute the script by entering its name:
```
.\harden.ps1
```

---

## Execution Modes

When prompted, choose one of the following modes:

### **1. Automatic Mode (`auto`)**
- Runs all tasks automatically, with a summary provided at the end.
- Ideal for fully automating security tasks in environments where manual confirmation is unnecessary.

### **2. Interactive Mode (`ask`)**
- Asks for user confirmation before executing each task.
- Useful for systems where careful oversight of changes is required.

### **3. Verification Mode (`verify`)**
- Inspects the current system configuration and reports the status of each task without making changes.
- Recommended for auditing or assessing system security posture.

---

## Post-Execution Actions

### **Restart Notification**
- If a restart is required for some changes to take effect, the script will notify you at the end.

### **Review Results**
- Analyze the task completion summary displayed in the PowerShell window to ensure all desired actions were successfully applied.

---

### **Task Categories**
1. **System Configuration Tasks**: Core system updates.
2. **Security Policies and Features Hardening**: Advanced security measures.
3. **Application Hardening Tasks**: Enhancements for secure browsing and application usage.
4. **System Hardening Tasks**: Optimizations for disabling unnecessary features and improving efficiency.

---

## Additional Notes

1. The `Set-ExecutionPolicy` change is session-specific and reverts when the PowerShell window is closed.
2. Always test the script in a non-production environment to ensure compatibility with your setup.
3. Some settings may not align with every use case—review task descriptions carefully.
