// main.js

document.getElementById("myForm").addEventListener("submit", function(event) {
    event.preventDefault(); // Prevent default form submission
    
    // Retrieve form data
    var name = document.getElementById("cln").value;
    var phone = document.getElementById("clp").value;
    var email = document.getElementById("cle").value;

    // Store data in localStorage to access in the next page
    localStorage.setItem("name", name);
    localStorage.setItem("phone", phone);
    localStorage.setItem("email", email);

    // Navigate to the next page
    window.location.href = "./details.html";
});
