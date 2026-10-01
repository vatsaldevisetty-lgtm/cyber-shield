function startScan() {

    const input = document.getElementById("websiteURL");

    const url = input.value.trim();

    if (!url) {
        alert("Please enter a website URL.");
        return;
    }

    let parsedURL;

    try {
        parsedURL = new URL(url);
    } catch {
        alert("Please enter a valid URL.");
        return;
    }

    document.getElementById("results")
        .classList.remove("hidden");

    document.getElementById("scannedURL")
        .textContent = parsedURL.href;

    const usesHTTPS =
        parsedURL.protocol === "https:";

    document.getElementById("httpsStatus")
        .textContent =
        usesHTTPS ? "PASS" : "REVIEW";

    document.getElementById("cspStatus")
        .textContent = "SERVER CHECK";

    document.getElementById("hstsStatus")
        .textContent = "SERVER CHECK";

    document.getElementById("contentStatus")
        .textContent = "SERVER CHECK";

    document.getElementById("referrerStatus")
        .textContent = "SERVER CHECK";

    let score = usesHTTPS ? 20 : 0;

    document.getElementById("score")
        .textContent = score + "%";

    document.getElementById("results")
        .scrollIntoView({
            behavior: "smooth"
        });
}
