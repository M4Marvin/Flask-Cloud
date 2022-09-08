
// Elements for taking the snapshot
var video = document.getElementById('video');
var canvas = document.getElementById('canvas');
var context = canvas.getContext('2d');
var failCount = 0;

// Get access to the camera!
if(navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
    // Not adding `{ audio: true }` since we only want video now
    navigator.mediaDevices.getUserMedia({ video: true }).then(function(stream) {
        //video.src = window.URL.createObjectURL(stream);
        video.srcObject = stream;
        video.play();
    });
}

// Trigger photo take
document.getElementById("send").addEventListener("click", function() {
    context.drawImage(video, 0, 0, 640, 480); // copy frame from <video>
    canvas.toBlob(upload, "image/jpeg");  // convert to file and execute function `upload`
});

function upload(file) {
    // create form and append file
    var formdata =  new FormData();
    formdata.append("face", file);
    formdata.append("user_id", "{{ user_id }}");

    // create AJAX requests POST with file
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "{{ url_for('auth.login') }}");
    xhr.onload = function() {
        if(this.status = 200) {
            console.log(this.response);
            if (this.response == "Success") {
                alert("Face authentication successful!");
                window.location.replace("{{ url_for('index') }}");
            }
        }
        else {
            console.error(xhr);
            else if (failCount < 3) {
                alert("Face authentication failed. Please try again.");
                failCount++;
            }
            else {
                alert("Too many failed attempts. Account has been locked. \nPlease contact the administrator.");
                window.location.replace("{{ url_for('auth.login') }}");
            }
        }
    };
    xhr.send(formdata);
}
