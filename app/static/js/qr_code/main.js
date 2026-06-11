const app = document.querySelector('.app'), 
form = document.querySelector('form'),
imgQrCode = document.querySelector('form img'),
uploadQr = document.querySelector('.content'),
textUploading = uploadQr.querySelector('p'),
inputFile = document.querySelector('input'),
details = document.querySelector('.details'),
textArea = details.querySelector('textarea'),
btnClose = document.querySelector('.close'),
btnCopy = document.querySelector('.copy');


inputFile.addEventListener('change', (e) => {
  let file = e.target.files[0];
  let formData = new FormData();
  formData.append('file', file);
  let urlFile = URL.createObjectURL(file);

  fetchReq(formData, urlFile);
});
uploadQr.addEventListener('click', () => inputFile.click());


btnClose.addEventListener('click', () => {
  textUploading.textContent = "Upload QR Code To Scan";
  imgQrCode.src = '';
  imgQrCode.alt = '';
  uploadQr.classList.remove('hidden');
  details.classList.remove('active');
  app.classList.remove('change-height');
  setTimeout(() => {
    window.location.reload();
  },500)
})
btnCopy.addEventListener('click', () => {
  navigator.clipboard.writeText(textArea.textContent);
})

function fetchReq(formData, urlFile) {
  textUploading.textContent = "Scanning QR Code...";
  fetch('http://api.qrserver.com/v1/read-qr-code/', {
    method: "POST",
    body: formData
  })
  .then(res => res.json())
  .then(result => {
    let data = result[0].symbol[0];
    console.log(data);
    if (data.error === null) {
      uploadQr.classList.add('hidden');
      imgQrCode.src = urlFile;
      imgQrCode.alt = "Qr-Code";

      details.classList.add('active');
      textArea.textContent = data.data;

      app.classList.add('change-height');
    }
    else{
      // Eorr
      textUploading.textContent = "Couldn't Scan QR Code";
    }
  })
  .catch(() => console.log("Eorr Api"))
}