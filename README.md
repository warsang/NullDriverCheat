# NullDriverCheat
My implementation for Windows 11 of Null's Driver Cheat.
Series available here:
https://www.youtube.com/watch?v=KNGr4m99PTU

This has a couple of minor changes; we use NtOpenCompositionSurfaceSectionInfo to avoid detection and a different memory pool tag.
Could potentially look at encrypting strings to hide this a little bit better in Kernel mem.
Honestly, while this works, it'll probably get detected by EAC pretty quickly once the cheat becomes popular and they write a sig for the driver.
