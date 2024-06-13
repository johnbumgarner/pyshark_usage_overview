document.addEventListener('DOMContentLoaded', function () {
    var clipboard = new ClipboardJS('.copy-btn', {
        target: function (trigger) {
            return trigger.parentElement.querySelector('code');
        }
    });

    clipboard.on('success', function (e) {
        e.clearSelection();
        alert('Code copied to clipboard');
    });

    clipboard.on('error', function (e) {
        alert('Failed to copy code');
    });
});