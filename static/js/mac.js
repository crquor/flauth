// email handler

$(document).ready(function () {

    $("#postchem").submit(function (event) {

        event.preventDefault();

        btnText = document.getElementById("btn-text"); let btnSpinner = document.getElementById("btn-spinner");
        btnText.classList.add("d-none"); btnSpinner.classList.remove("d-none");
        let alertBox = document.getElementById("alertBox");
        let alertMessage = document.getElementById("alert-message");

        $.ajax({

            url: "/account/change-email",
            type: "post",
            data: $(this).serialize(),
            dataType: "json",
            success: function (response) {
                if (response.error) {
                    alertMessage.textContent = response.error;
                    alertBox.classList.remove("d-none", "alert-success", "alert-danger");
                    alertBox.classList.add("alert-warning");
                }
                else {
                    $('#postchem')[0].reset();
                    alertMessage.textContent = response.success;
                    alertBox.classList.remove("d-none", "alert-warning", "alert-danger");
                    alertBox.classList.add("alert-success");
                    setTimeout(function () {
                        window.location.reload();
                    }, 5000);
                }
            },
            error: function () {
                alertMessage.textContent = "An unexpected error occurred";
                alertBox.classList.remove("d-none", "alert-success", "alert-warning");
                alertBox.classList.add("alert-danger");
            },

            complete: function () {
                btnText.classList.remove("d-none");
                btnSpinner.classList.add("d-none");
            }

        });
    });

});

// postchpwd handler
$(document).ready(function () {

    $("#postchpwd").submit(function (event) {

        event.preventDefault();

        btnText = document.getElementById("btn-text1");
        let btnSpinner = document.getElementById("btn-spinner1");
        btnText.classList.add("d-none"); btnSpinner.classList.remove("d-none");
        let alertBox = document.getElementById("alertBox1");
        let alertMessage = document.getElementById("alert-message1");

        $.ajax({

            url: "/account/change-password",
            type: "post",
            data: $(this).serialize(),
            dataType: "json",
            success: function (response) {
                if (response.error) {
                    alertMessage.textContent = response.error;
                    alertBox.classList.remove("d-none", "alert-success", "alert-danger");
                    alertBox.classList.add("alert-warning");
                }
                else {
                    $('#postchpwd')[0].reset();
                    alertMessage.textContent = response.success;
                    alertBox.classList.remove("d-none", "alert-warning", "alert-danger");
                    alertBox.classList.add("alert-success");
                    setTimeout(function () {
                        window.location.reload();
                    }, 5000);
                }
            },
            error: function () {
                alertMessage.textContent = "An unexpected error occurred";
                alertBox.classList.remove("d-none", "alert-success", "alert-warning");
                alertBox.classList.add("alert-danger");
            },

            complete: function () {
                btnText.classList.remove("d-none");
                btnSpinner.classList.add("d-none");
            }

        });
    });

});

// Account deletion
$(document).ready(function () {

    $("#postdelac").submit(function (event) {
        event.preventDefault();

        btnText = document.getElementById("btn-text2");
        let btnSpinner = document.getElementById("btn-spinner2");
        btnText.classList.add("d-none"); btnSpinner.classList.remove("d-none");
        let alertBox = document.getElementById("alertBox2");
        let alertMessage = document.getElementById("alert-message2");

        $.ajax({
            url: "/account/delete-account",
            type: "POST",
            dataType: "json",
            data: $(this).serialize(),
            success: function (response) {
                if (response.error) {
                    alertMessage.textContent = response.error;
                    alertBox.classList.remove("d-none", "alert-success", "alert-danger");
                    alertBox.classList.add("alert-warning");
                }
                else {
                    $('#postdelac')[0].reset();
                    alertMessage.textContent = response.success;
                    alertBox.classList.remove("d-none", "alert-warning", "alert-danger");
                    alertBox.classList.add("alert-success");
                    setTimeout(function () {
                        window.location.href = "/auth/login";
                    }, 5000);
                }
            },
            error: function () {
                alertMessage.textContent = "An unexpected error occurred";
                alertBox.classList.remove("d-none", "alert-success", "alert-warning");
                alertBox.classList.add("alert-danger");

            },
            complete: function () {
                btnText.classList.remove("d-none");
                btnSpinner.classList.add("d-none");
            }
        });


    });

});


// 2fa handler

document.getElementById("enable-2fa").addEventListener("change", function () {
    if (this.checked) {
        fetch("/account/enable-secondary-verification", { method: "POST" })
            .then(response => response.json())
            .then(data => {
                if (data.qr_code) {
                    document.getElementById("qrcode-img").src = "data:image/png;base64," + data.qr_code;
                    document.getElementById("value").textContent = data.secret_key;
                    document.getElementById("fa-enabled").style.display = "block";
                }
            });
    }
    else {
        $.ajax({
            url: "/account/disable-2fa",
            type: "POST",
            success: function () {
                window.location.reload();
            },
            error: function () {
                alert("Something went wrong");
            }
        })
    }
});


// 2fa verification handler

// Account deletion
$(document).ready(function () {

    $("#postsecver").submit(function (event) {
        event.preventDefault();

        btnText = document.getElementById("btn-text3");
        let btnSpinner = document.getElementById("btn-spinner3");
        btnText.classList.add("d-none"); btnSpinner.classList.remove("d-none");
        let alertBox = document.getElementById("alertBox3");
        let alertMessage = document.getElementById("alert-message3");

        $.ajax({
            url: "/account/verify-2fa",
            type: "POST",
            dataType: "json",
            data: $(this).serialize(),
            success: function (response) {
                if (response.error) {
                    alertMessage.textContent = response.error;
                    alertBox.classList.remove("d-none", "alert-success", "alert-danger");
                    alertBox.classList.add("alert-warning");
                }
                else {
                    $('#postsecver')[0].reset();
                    alertMessage.textContent = response.success;
                    alertBox.classList.remove("d-none", "alert-warning", "alert-danger");
                    alertBox.classList.add("alert-success");
                    setTimeout(function () {
                        window.location.reload();
                    }, 5000);
                }
            },
            error: function () {
                alertMessage.textContent = "An unexpected error occurred";
                alertBox.classList.remove("d-none", "alert-success", "alert-warning");
                alertBox.classList.add("alert-danger");

            },
            complete: function () {
                btnText.classList.remove("d-none");
                btnSpinner.classList.add("d-none");
            }
        });


    });

});