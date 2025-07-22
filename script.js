// Initialize Three.js scene for 3D elements
function initThreeScene() {
  // This would be a more complex implementation in a real project
  console.log("3D scene initialized");
}

// Show notification badge
function showNotification() {
  const badge = document.getElementById("notificationBadge");
  badge.classList.add("show");
}

// Modal handling
const signupModal = document.getElementById("signupModal");
const loginModal = document.getElementById("loginModal");
const communityModal = document.getElementById("communityModal");

// Sign up modal controls
const signupBtn = document.getElementById("signupBtn");
const closeSignupModal = document.getElementById("closeSignupModal");
const switchToLogin = document.getElementById("switchToLogin");

signupBtn.addEventListener("click", function () {
  signupModal.classList.add("show");
});

closeSignupModal.addEventListener("click", function () {
  signupModal.classList.remove("show");
});

switchToLogin.addEventListener("click", function () {
  signupModal.classList.remove("show");
  loginModal.classList.add("show");
});

// Login modal controls
const loginBtn = document.getElementById("loginBtn");
const closeLoginModal = document.getElementById("closeLoginModal");
const switchToSignup = document.getElementById("switchToSignup");

loginBtn.addEventListener("click", function () {
  loginModal.classList.add("show");
});

closeLoginModal.addEventListener("click", function () {
  loginModal.classList.remove("show");
});

switchToSignup.addEventListener("click", function () {
  loginModal.classList.remove("show");
  signupModal.classList.add("show");
});

// Community modal controls
const joinCommunityBtn = document.getElementById("joinCommunityBtn");
const closeCommunityModal = document.getElementById("closeCommunityModal");

joinCommunityBtn.addEventListener("click", function () {
  communityModal.classList.add("show");
});

closeCommunityModal.addEventListener("click", function () {
  communityModal.classList.remove("show");
});

// Helper to show feedback in modals
function showFormMessage(form, message, isError = true) {
  let msgElem = form.querySelector(".form-message");
  if (!msgElem) {
    msgElem = document.createElement("div");
    msgElem.className = "form-message";
    msgElem.style.margin = "10px 0";
    msgElem.style.fontSize = "1rem";
    form.insertBefore(msgElem, form.firstChild);
  }
  msgElem.textContent = message;
  msgElem.style.color = isError ? "#dc2626" : "#16a34a";
}

// Toast notification for bottom popup
function showToast(message, isError = false) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.remove('bg-green-600', 'bg-red-600');
  toast.classList.add(isError ? 'bg-red-600' : 'bg-green-600');
  toast.style.opacity = '1';
  toast.style.pointerEvents = 'auto';
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.pointerEvents = 'none';
  }, 3000);
}

// Utility to decode JWT (for user info if needed)
function parseJwt(token) {
  try {
    const base64Url = token.split(".")[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map(function (c) {
          return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
        })
        .join("")
    );
    return JSON.parse(jsonPayload);
  } catch (e) {
    return null;
  }
}

function updateAuthUI() {
  const token = localStorage.getItem("thriveher_token");
  const loginBtn = document.getElementById("loginBtn");
  const signupBtn = document.getElementById("signupBtn");
  const userGreeting = document.getElementById("userGreeting");
  const logoutBtn = document.getElementById("logoutBtn");

  if (token) {
    // Try to get user info from last login/signup, else decode JWT
    let user = JSON.parse(localStorage.getItem("thriveher_user") || "null");
    if (!user) {
      const payload = parseJwt(token);
      user = payload
        ? { name: payload.name || payload.email || "User" }
        : { name: "User" };
    }
    userGreeting.textContent = `Hi, ${user.name || user.email || "User"}!`;
    userGreeting.classList.remove("hidden");
    logoutBtn.classList.remove("hidden");
    loginBtn.classList.add("hidden");
    signupBtn.classList.add("hidden");
  } else {
    userGreeting.classList.add("hidden");
    logoutBtn.classList.add("hidden");
    loginBtn.classList.remove("hidden");
    signupBtn.classList.remove("hidden");
  }
}

document.getElementById("logoutBtn").addEventListener("click", function () {
  localStorage.removeItem("thriveher_token");
  localStorage.removeItem("thriveher_user");
  updateAuthUI();
});

// Signup form handler
const signupForm = document.getElementById("signupForm");
// OTP modal controls
const otpModal = document.getElementById("otpModal");
const closeOtpModal = document.getElementById("closeOtpModal");
const otpForm = document.getElementById("otpForm");
const otpInput = document.getElementById("otpInput");
const otpEmailInfo = document.getElementById("otpEmailInfo");
let pendingSignupEmail = "";

closeOtpModal.addEventListener("click", function () {
  otpModal.classList.remove("show");
  otpForm.reset();
  otpEmailInfo.textContent = "";
  pendingSignupEmail = "";
});

// Patch signup form handler for OTP flow
signupForm.addEventListener("submit", async function (e) {
  e.preventDefault();
  const name = document.getElementById("name").value.trim();
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;
  const age = document.getElementById("age").value;

  try {
    const res = await fetch("http://localhost:5000/api/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, email, password, age }),
    });
    const data = await res.json();
    if (res.ok && data.message && data.message.includes("OTP")) {
      // OTP sent, show OTP modal
      pendingSignupEmail = email;
      otpModal.classList.add("show");
      otpEmailInfo.textContent = `OTP sent to ${email}`;
      signupModal.classList.remove("show");
      signupForm.reset();
    } else if (res.ok && data.token) {
      // fallback: direct signup (shouldn't happen with OTP flow)
      localStorage.setItem("thriveher_token", data.token);
      localStorage.setItem("thriveher_user", JSON.stringify(data.user));
      showFormMessage(
        signupForm,
        "Signup successful! Welcome, " + data.user.name + ".",
        false
      );
      setTimeout(() => {
        signupModal.classList.remove("show");
        signupForm.reset();
        updateAuthUI();
        window.location.href = "dashboard.html";
      }, 1200);
    } else {
      showFormMessage(signupForm, data.message || "Signup failed.");
    }
  } catch (err) {
    showFormMessage(signupForm, "Network error. Please try again.");
  }
});

// OTP form handler
otpForm.addEventListener("submit", async function (e) {
  e.preventDefault();
  const otp = otpInput.value.trim();
  if (!pendingSignupEmail) {
    showFormMessage(otpForm, "No signup in progress.");
    return;
  }
  try {
    const res = await fetch("http://localhost:5000/api/verify-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: pendingSignupEmail, otp }),
    });
    const data = await res.json();
    if (res.ok && data.token) {
      localStorage.setItem("thriveher_token", data.token);
      localStorage.setItem("thriveher_user", JSON.stringify(data.user));
      showFormMessage(
        otpForm,
        "Signup complete! Welcome, " + data.user.name + ".",
        false
      );
      setTimeout(() => {
        otpModal.classList.remove("show");
        otpForm.reset();
        otpEmailInfo.textContent = "";
        pendingSignupEmail = "";
        updateAuthUI();
        window.location.href = "dashboard.html";
      }, 1200);
    } else {
      showFormMessage(otpForm, data.message || "OTP verification failed.");
    }
  } catch (err) {
    showFormMessage(otpForm, "Network error. Please try again.");
  }
});

// Login form handler
const loginForm = document.getElementById("loginForm");
loginForm.addEventListener("submit", async function (e) {
  e.preventDefault();
  const email = document.getElementById("loginEmail").value.trim();
  const password = document.getElementById("loginPassword").value;

  try {
    const res = await fetch("http://localhost:5000/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (res.ok) {
      localStorage.setItem("thriveher_token", data.token);
      localStorage.setItem("thriveher_user", JSON.stringify(data.user));
      showFormMessage(
        loginForm,
        "Login successful! Welcome back, " + data.user.name + ".",
        false
      );
      setTimeout(() => {
        loginModal.classList.remove("show");
        loginForm.reset();
        // Optionally, update UI to reflect logged-in state
        updateAuthUI();
        window.location.href = "dashboard.html";
      }, 1200);
    } else {
      showFormMessage(loginForm, data.message || "Login failed.");
    }
  } catch (err) {
    showFormMessage(loginForm, "Network error. Please try again.");
  }
});

document
  .getElementById("communityForm")
  .addEventListener("submit", function (e) {
    e.preventDefault();
    // This would connect to the backend in a real implementation
    alert(
      "This is a prototype. In the full version, this would add you to our community."
    );
    communityModal.classList.remove("show");
  });

// Initialize the page
document.addEventListener("DOMContentLoaded", function () {
  // Initialize Three.js scene
  initThreeScene();

  // Show notification after a delay
  setTimeout(showNotification, 3000);

  // Initialize GSAP animations
  if (typeof gsap !== "undefined") {
    gsap.from(".hero-content h1", {
      opacity: 0,
      y: 50,
      duration: 1,
      ease: "power3.out",
    });

    gsap.from(".hero-content p", {
      opacity: 0,
      y: 30,
      duration: 1,
      delay: 0.3,
      ease: "power3.out",
    });

    gsap.from(".btn-primary", {
      opacity: 0,
      y: 20,
      duration: 1,
      delay: 0.6,
      ease: "power3.out",
    });
  }
  updateAuthUI();
});

// Close modals when clicking outside the modal content
window.addEventListener("click", function (event) {
  if (event.target === signupModal) {
    signupModal.classList.remove("show");
  }
  if (event.target === loginModal) {
    loginModal.classList.remove("show");
  }
  if (event.target === communityModal) {
    communityModal.classList.remove("show");
  }
});

// Forgot Password button/modal controls
const forgotPasswordBtn = document.getElementById("forgotPasswordBtn");
if (forgotPasswordBtn) {
  forgotPasswordBtn.addEventListener("click", openForgotModal);
}

const closeForgotPasswordModal = document.getElementById("closeForgotPasswordModal");
if (closeForgotPasswordModal) {
  closeForgotPasswordModal.addEventListener("click", closeForgotModal);
}


// Modal functions
function openForgotModal() {
  const modal = document.getElementById("forgotPasswordModal");
  const loginModal = document.getElementById("loginModal");
  const signupModal = document.getElementById("signupModal");
  modal.classList.add("show");
  if (loginModal) loginModal.classList.remove("show");
  if (signupModal) signupModal.classList.remove("show");
}

function closeForgotModal() {
  const modal = document.getElementById("forgotPasswordModal");
  modal.classList.remove("show");
  document.getElementById("forgotPasswordForm").classList.remove("hidden");
  document.getElementById("verifyResetOTPForm").classList.add("hidden");
}
// Forgot Password: Step 1 - Send OTP
document.getElementById("forgotPasswordForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("resetEmail").value;

  try {
    const res = await fetch("http://localhost:5000/api/request-password-reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    showToast(data.message, !res.ok);

    if (res.ok) {
      document.getElementById("forgotPasswordForm").classList.add("hidden");
      document.getElementById("verifyResetOTPForm").classList.remove("hidden");
    }
  } catch (err) {
    showToast("Error sending OTP.", true);
  }
});

// Forgot Password: Step 2 - Verify OTP
document.getElementById("verifyResetOTPForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("resetEmail").value;
  const otp = document.getElementById("resetOtp").value;
  const newPassword = document.getElementById("resetNewPassword").value;
  const confirmPassword = document.getElementById("resetConfirmPassword").value;

  if (newPassword !== confirmPassword) {
    showToast("Passwords do not match.", true);
    return;
  }

  try {
    const res = await fetch("http://localhost:5000/api/verify-reset-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, otp, newPassword }),
    });
    const data = await res.json();
    showToast(data.message, !res.ok);

    if (res.ok) {
      closeForgotModal();
    }
  } catch (err) {
    showToast("Error verifying OTP.", true);
  }
});
