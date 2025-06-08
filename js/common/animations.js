// Animation on scroll for sections and header/footer
function revealOnScroll() {
    const animatedElements = document.querySelectorAll('.animate-fade-in, .animate-slide-up');
    const windowHeight = window.innerHeight;
    animatedElements.forEach(el => {
        const rect = el.getBoundingClientRect();
        if (rect.top < windowHeight - 60) {
            el.classList.add('visible');
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    revealOnScroll();
    window.addEventListener('scroll', revealOnScroll);
}); 