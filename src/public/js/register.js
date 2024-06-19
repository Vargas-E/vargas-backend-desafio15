console.log("error:", error);

if (error) {
    Swal.fire({
        title: 'Email already in use',
        icon: 'error',
        confirmButtonText: 'OK',
        color: "#009B72",
        background: "#0c1b1b"
      })
}