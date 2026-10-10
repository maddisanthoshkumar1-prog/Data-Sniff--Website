window.addEventListener("scroll", () => {

    const cards = document.querySelectorAll(
        ".about-card,.feature-card,.flow-card,.stat-card,.tech-card"
    );

    cards.forEach(card => {

        const position = card.getBoundingClientRect().top;

        if(position < window.innerHeight - 100){

            card.style.opacity = "1";
            card.style.transform = "translateY(0)";

        }
        const topBtn=document.getElementById("topBtn");

topBtn.onclick=()=>{

window.scrollTo({

top:0,

behavior:"smooth"

});

};

    });

});