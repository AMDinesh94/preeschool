function switchTab(tabId) {
    const tabs = document.querySelectorAll('.tab-content');
    const buttons = document.querySelectorAll('.tab');

    tabs.forEach(tab => {
        tab.classList.add('hidden');
    });

    buttons.forEach(button => {
        button.classList.remove('active');
    });

    document.getElementById(tabId).classList.remove('hidden');
    document.querySelector(`button[onclick="switchTab('${tabId}')"]`).classList.add('active');
}
