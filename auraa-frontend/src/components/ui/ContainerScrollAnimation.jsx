import React, { useRef, useState, useEffect } from "react";
import { useScroll, useTransform, motion } from "framer-motion";

export const ContainerScroll = ({ titleComponent, children }) => {
    const containerRef = useRef(null);
    const { scrollYProgress } = useScroll({ target: containerRef });
    const [isMobile, setIsMobile] = useState(false);

    useEffect(() => {
        const checkMobile = () => setIsMobile(window.innerWidth <= 768);
        checkMobile();
        window.addEventListener("resize", checkMobile);
        return () => window.removeEventListener("resize", checkMobile);
    }, []);

    const scaleDimensions = () => (isMobile ? [0.7, 0.9] : [1.05, 1]);
    const rotate = useTransform(scrollYProgress, [0, 1], [20, 0]);
    const scale = useTransform(scrollYProgress, [0, 1], scaleDimensions());
    const translate = useTransform(scrollYProgress, [0, 1], [0, -100]);

    return (
        <div className="h-[60rem] md:h-[80rem] flex items-center justify-center relative p-2 md:p-20" ref={containerRef}>
            <div className="py-10 md:py-40 w-full relative" style={{ perspective: "1000px" }}>
                <Header translate={translate} titleComponent={titleComponent} />
                <Card rotate={rotate} translate={translate} scale={scale}>
                    {children}
                </Card>
            </div>
        </div>
    );
};

export const Header = ({ translate, titleComponent }) => (
    <motion.div style={{ translateY: translate }} className="max-w-5xl mx-auto text-center">
        {titleComponent}
    </motion.div>
);

export const Card = ({ rotate, scale, children }) => {
    return (
        <motion.div
            style={{
                rotateX: rotate,
                scale,
                boxShadow:
                    "0 0 #0000004d, 0 9px 20px #0000004a, 0 37px 37px #00000042, 0 84px 50px #00000026, 0 149px 60px #0000000a, 0 233px 65px #00000003",
            }}
            className="max-w-5xl -mt-12 mx-auto h-[30rem] md:h-[40rem] w-full border-[8px] border-[#222] p-2 bg-[#111] rounded-[30px] shadow-2xl relative"
        >
            {/* Hardware: Bezel & Camera */}
            <div className="absolute inset-0 rounded-[22px] border border-white/10 pointer-events-none" />
            <div className="absolute top-3 left-1/2 -translate-x-1/2 w-20 h-1.5 bg-[#1a1a1a] rounded-full z-20 flex items-center justify-center">
                <div className="w-1 h-1 bg-[#333] rounded-full" />
            </div>

            {/* Screen Container */}
            <div className="h-full w-full overflow-hidden rounded-[20px] bg-[#050505] relative group">

                {/* Effect: Glass Glare (Top Right) */}
                <div className="absolute top-0 right-0 w-[300px] h-[300px] bg-gradient-to-bl from-white/10 via-transparent to-transparent pointer-events-none z-30 rounded-tr-[20px]" />

                {/* Content */}
                {children}
            </div>
        </motion.div>
    );
};
