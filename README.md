# Zephyr Driver for OpenTitan AES IP

This repo is an out-of-tree Zephyr RTOS driver for the [OpenTitan](https://opentitan.org/) [AES hardware block](https://opentitan.org/book/hw/ip/aes/index.html). With this driver you can offload AES encryption and decryption directly to hardware, using the AES block on OpenTitan Earl Grey or any SoC implementing the OpenTitan AES IP.

For now the driver only supports ECB mode, will add support for other AES modes later on.

---
---
# Learn How To Create Your Own Zephyr Driver

When I first started looking for tutorials on how to write a driver, they all felt really high-level to me. There aren't many tutorials out there, and the ones that exist assume the reader already has a fair amount of background knowledge. So in this one, I tried to briefly explain all the concepts that might be new to you. This is for anyone who wants to write a Zephyr RTOS driver but doesn't know where to start. You don't need prior driver experience, just basic C knowledge and a general idea of what a microcontroller is.

Hope you enjoy reading! Let me know if there are any mistakes...



## Get Familiar With the Concepts First!
To run software on hardware you need an operating system. For microcontrollers specifically, we typically use a real-time operating system (RTOS), a type of OS that prioritizes determinism, time-sensitive operations, and resource-constrained devices. Just like there are many general-purpose operating systems you already know: Windows, Linux, macOS. There are also many RTOSes, and Zephyr is just one of them. Zephyr is becoming really popular these days for many reasons beyond being fully open source: its modularity, broad board support, and security-first design.


> 💡 **What is an RTOS?**   
> A regular OS like Windows or Linux is designed for comfort, it tries to do many things at once and doesn't guarantee when exactly each task runs. An RTOS is designed for predictability, it guarantees that a task runs within a specific time window. This matters a lot when you're controlling hardware: if your code is supposed to read a sensor every 10ms, a 50ms delay could break everything. Zephyr, FreeRTOS, and ThreadX are all examples of RTOSes.


For the OS to work, it must recognize the hardware and know how to communicate with it. The most fundamental way software talks to hardware is through **registers**. Each hardware IP has its own set of control and status registers, sitting at specific offsets from a base address. A **driver** is the piece of software that knows where those registers are, what writing to them does, and what reading them back means. In short: a driver is the bridge between the OS and a physical piece of hardware.

> 💡 **What are registers?**   
> Registers are small memory locations built directly into the hardware. Writing a specific value to a register tells the hardware to do something (like start an encryption operation). Reading a register tells you the hardware's current state (like whether it's done or idle). Every hardware block has its own set of registers sitting at fixed addresses in memory, this is called memory-mapped I/O.

Some drivers are called **bare-metal** drivers, where software reads and writes directly to physical memory addresses with no abstraction layer. Other drivers, like this one, are written against an **API provided by the OS kernel** (in our case, [Zephyr's `crypto` API](https://docs.zephyrproject.org/latest/services/crypto/api/index.html)). This approach is more work upfront, but it pays off when your driver is part of a larger system: the kernel and other subsystems can interact with your hardware through a standard interface, without needing to know anything about the specific registers underneath.

Each hardware IP block has different registers and different functionality, which means for every hardware block or board, you need a new driver. Check [zephyr/drivers](https://github.com/zephyrproject-rtos/zephyr/tree/main/drivers) to see how many drivers Zephyr supports. The repo is organized so that all drivers for a certain functionality, like Bluetooth IPs in a folder, and all the UART IPs in another and so on. In our case, my driver is an AES driver (a crypto algorithm that encrypts and decrypts data), so it sits in the [`crypto`](https://github.com/zephyrproject-rtos/zephyr/tree/main/drivers/crypto) folder.

> 💡 **What is AES?**  
> AES (Advanced Encryption Standard) is the most widely used encryption algorithm in the world. It takes a block of data (16 bytes) and a key (128 or 256 bits) and scrambles the data in a way that's practically impossible to reverse without the same key. Your browser uses it for HTTPS, your phone uses it for storage encryption. Running it in hardware instead of software is much faster and more power-efficient.

Now the first thing you might think is: okay, let me fork the Zephyr repo, implement my driver, and submit a PR. That's completely valid, and it's called an **"in-tree"** driver. But why deal with the hassle of cloning a repo that's gigabytes worth of files onto your local machine? There's an easier way called **"out-of-tree"**, which means you create your own separate repo. Zephyr's build tool `west` handles pulling it in and merging it with the main Zephyr source at build time.

> 💡 **What is west?**   
> west is Zephyr's command-line build and workspace management tool. Think of it like npm but for embedded Zephyr projects. It reads a west.yml manifest file that lists all the repos your project depends on, fetches them, and makes them all available to the build system at once. When you add your out-of-tree driver repo to the manifest, west pulls it in automatically every time someone sets up the project.

## Zephyr out of tree project folders structure
To implement our out-of-tree driver we have to follow **Zephyr's expected folder structure**:
```bash
your-driver-repo/  
│
├── drivers/ <subsystem>/  
│ ├── main-driver-code.c   # Most Important File!
│ ├── Kconfig  
│ └── CMakeLists.txt
│
├── dts/ bindings/  
│ └── <subsystem>/ vendor,device.yaml
│ └── vendor-prefixes.txt
│
├── zephyr/ module.yml
└── CMakeLists.txt
```

> 💡 **What is a Devicetree?**  
> A Devicetree (`.dts` file) is a text file that describes your hardware to the OS — things like what peripherals exist, where they sit in memory, and which driver should handle them. Instead of your driver hardcoding a register address like `0x411f0000`, the devicetree file declares it and the driver reads it at build time. Think of it as a map of your board that the kernel consults before booting. As a unified point to your IP Base configurations like Base Address.

> 💡 **What is a Devicetree Binding?**  
> A binding file (`.yaml`) is the _schema_ for a devicetree node. It tells Zephyr: "a node with `compatible = "lowrisc,opentitan-aes"` is allowed to have these properties, with these types." Without a binding, Zephyr doesn't know how to validate or parse your hardware node. It's the contract between the hardware description and the driver.

> 💡 **What is Kconfig?**  
> Kconfig is Zephyr's configuration system. It lets you expose `CONFIG_` options for your driver, like `CONFIG_CRYPTO_OPENTITAN_MAX_SESSION`, that users can toggle on/off or set values for without touching your source code. When someone runs `west build`, Kconfig decides which drivers get compiled in and which don't.

I know it may seem confusing at first, but we'll explain what each file means and what to write in it.

Open the repo folders in another tab and try to map what you read and learn here to the actual code. In our case, the **subsystem** is `crypto` and the **vendor** is `lowrisc` and the **device** is `opentitan-aes`, so the structure maps directly to what you see in this repo. 

We'll focus for now on the main `.c` file implementation, as the other files are mostly boilerplate to satisfy Zephyr's build system.

## Let's Start Writing the Actual Driver's Code!
The first thing I did when I wanted to write my AES driver was open multiple tabs of different AES driver implementations, read through them carefully, compare them to each other, and then sketch out a base file structure. What I found is that this structure is basically the same across almost every Zephyr driver, whether in the `crypto` subsystem or any other. Some drivers may have one or two extra sections (UART for example needs interrupt handling), but this skeleton covers 90% of them:

```
// ------------------------------------------------------
// 1. Device Tree Compatibility
// ------------------------------------------------------

// ------------------------------------------------------
// 2. Header Includes
// ------------------------------------------------------

// ------------------------------------------------------
// 3. Register Offsets and Bitmasks (macro)
// ------------------------------------------------------

// ------------------------------------------------------
// 4. Configuration Structure
// ------------------------------------------------------

// ------------------------------------------------------
// 5. Initialization and Reset
// ------------------------------------------------------

// ------------------------------------------------------
// 6. Read and Write Functions & Helpers
// ------------------------------------------------------

// ------------------------------------------------------
// 7. AES Modes - ECB only for v1, CBC in v2
// ------------------------------------------------------

// ------------------------------------------------------
// 8. Session Management
// ------------------------------------------------------

// ------------------------------------------------------
// 9. Hardware Capability Query
// ------------------------------------------------------

// ------------------------------------------------------
// 10. Hooking up the API
// ------------------------------------------------------

// ------------------------------------------------------
// 11. Device Instantiation 
// ------------------------------------------------------

```

**The sections follow a natural flow.** Sections 1–4 are all declaration: you tell Zephyr what your hardware is, what headers you need, what its registers look like, and how you'll store its state in memory. Sections 5–8 are the actual logic: you initialize the hardware, write the read/write helpers, implement the crypto operations, and manage sessions. Sections 9–11 are the wiring: you tell Zephyr what your hardware can do, plug your functions into the API struct, and register the device with the kernel. **describe → implement → connect.** We'll explore each section in depth:
