import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence, MotionConfig } from "framer-motion";
import { ChevronDown, Shield, AlertTriangle, Info, AlertOctagon, Layers } from "lucide-react";
import { cn } from "../../lib/utils";

// Custom hook for click outside detection
function useClickAway(ref, handler) {
    useEffect(() => {
        const listener = (event) => {
            if (!ref.current || ref.current.contains(event.target)) {
                return;
            }
            handler(event);
        };

        document.addEventListener("mousedown", listener);
        document.addEventListener("touchstart", listener);

        return () => {
            document.removeEventListener("mousedown", listener);
            document.removeEventListener("touchstart", listener);
        };
    }, [ref, handler]);
}

// Button component
const Button = React.forwardRef(({ className, variant, children, ...props }, ref) => {
    return (
        <button
            ref={ref}
            className={cn(
                "inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2",
                "disabled:pointer-events-none disabled:opacity-50",
                variant === "outline" && "border border-neutral-700 bg-transparent",
                className
            )}
            {...props}
        >
            {children}
        </button>
    );
});
Button.displayName = "Button";

const categories = [
    { id: "All", label: "All Severities", icon: Layers, color: "#A06CD5" },
    { id: "Low", label: "Low", icon: Info, color: "#3B82F6" },         // Blue
    { id: "Medium", label: "Medium", icon: Shield, color: "#EAB308" }, // Yellow
    { id: "High", label: "High", icon: AlertTriangle, color: "#F97316" }, // Orange
    { id: "Critical", label: "Critical", icon: AlertOctagon, color: "#EF4444" }, // Red
];

// Icon wrapper with animation
const IconWrapper = ({ icon: Icon, isHovered, color }) => (
    <motion.div
        className="w-4 h-4 mr-2 relative"
        initial={false}
        animate={isHovered ? { scale: 1.2 } : { scale: 1 }}
    >
        <Icon className="w-4 h-4" />
        {isHovered && (
            <motion.div
                className="absolute inset-0"
                style={{ color }}
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: 1, opacity: 1 }}
                transition={{ duration: 0.5, ease: "easeInOut" }}
            >
                <Icon className="w-4 h-4" strokeWidth={2} />
            </motion.div>
        )}
    </motion.div>
);

// Animation variants
const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
        opacity: 1,
        transition: {
            when: "beforeChildren",
            staggerChildren: 0.1,
        },
    },
};

const itemVariants = {
    hidden: { opacity: 0, y: -10 },
    visible: {
        opacity: 1,
        y: 0,
        transition: {
            duration: 0.3,
            ease: [0.25, 0.1, 0.25, 1],
        },
    },
};

export default function FluidDropdown({ selectedSeverity, onSeverityChange }) {
    const [isOpen, setIsOpen] = useState(false);
    // Find the category object that matches the selectedSeverity string data
    const currentCategory = categories.find(c => c.id === selectedSeverity) || categories[0];

    const [hoveredCategory, setHoveredCategory] = useState(null);
    const dropdownRef = useRef(null);

    useClickAway(dropdownRef, () => setIsOpen(false));

    const handleKeyDown = (e) => {
        if (e.key === "Escape") {
            setIsOpen(false);
        }
    };

    return (
        <MotionConfig reducedMotion="user">
            <div
                className="w-full md:w-48 relative z-20"
                ref={dropdownRef}
            >
                <Button
                    variant="outline"
                    onClick={() => setIsOpen(!isOpen)}
                    className={cn(
                        "w-full justify-between bg-black/50 text-neutral-400 font-normal",
                        "hover:bg-neutral-800 hover:text-neutral-200",
                        "focus:ring-2 focus:ring-neutral-700 focus:ring-offset-2 focus:ring-offset-black",
                        "transition-all duration-200 ease-in-out",
                        "border border-white/10 focus:border-neutral-700",
                        "h-10", // Matching input height
                        isOpen && "bg-neutral-800 text-neutral-200",
                    )}
                    aria-expanded={isOpen}
                    aria-haspopup="true"
                    type="button" // Prevent form submission if inside form
                >
                    <span className="flex items-center">
                        <IconWrapper
                            icon={currentCategory.icon}
                            isHovered={false}
                            color={currentCategory.color}
                        />
                        {currentCategory.label}
                    </span>
                    <motion.div
                        animate={{ rotate: isOpen ? 180 : 0 }}
                        transition={{ duration: 0.2 }}
                        className="flex items-center justify-center w-5 h-5 ml-2"
                    >
                        <ChevronDown className="w-4 h-4" />
                    </motion.div>
                </Button>

                <AnimatePresence>
                    {isOpen && (
                        <motion.div
                            initial={{ opacity: 1, y: 0, height: 0 }}
                            animate={{
                                opacity: 1,
                                y: 0,
                                height: "auto",
                                transition: {
                                    type: "spring",
                                    stiffness: 500,
                                    damping: 30,
                                    mass: 1,
                                },
                            }}
                            exit={{
                                opacity: 0,
                                y: 0,
                                height: 0,
                                transition: {
                                    type: "spring",
                                    stiffness: 500,
                                    damping: 30,
                                    mass: 1,
                                },
                            }}
                            className="absolute left-0 right-0 top-full mt-2 overflow-hidden"
                            onKeyDown={handleKeyDown}
                        >
                            <motion.div
                                className="w-full rounded-lg border border-white/10 bg-black/90 p-1 shadow-lg backdrop-blur-xl"
                                initial={{ borderRadius: 8 }}
                                animate={{
                                    borderRadius: 12,
                                    transition: { duration: 0.2 },
                                }}
                                style={{ transformOrigin: "top" }}
                            >
                                <motion.div
                                    className="py-2 relative"
                                    variants={containerVariants}
                                    initial="hidden"
                                    animate="visible"
                                >
                                    {/* Highlight Background */}
                                    <motion.div
                                        layoutId="hover-highlight"
                                        className="absolute inset-x-1 bg-neutral-800/80 rounded-md"
                                        initial={false}
                                        animate={{
                                            y: categories.findIndex((c) => (hoveredCategory || currentCategory.id) === c.id) * 40 +
                                                (categories.findIndex((c) => (hoveredCategory || currentCategory.id) === c.id) > 0 ? 0 : 0), // Adjusted offset calculation logic slightly if needed, simplifed here as spacing is uniform
                                            height: 40,
                                            opacity: hoveredCategory ? 1 : 0, // Only show highlight on hover, optional style choice
                                        }}
                                        transition={{
                                            type: "spring",
                                            bounce: 0.15,
                                            duration: 0.5,
                                        }}
                                    />

                                    {categories.map((category) => (
                                        <React.Fragment key={category.id}>
                                            <motion.button
                                                onClick={() => {
                                                    if (onSeverityChange) onSeverityChange(category.id);
                                                    setIsOpen(false);
                                                }}
                                                onHoverStart={() => setHoveredCategory(category.id)}
                                                onHoverEnd={() => setHoveredCategory(null)}
                                                className={cn(
                                                    "relative flex w-full items-center px-4 py-2.5 text-sm rounded-md",
                                                    "transition-colors duration-150",
                                                    "focus:outline-none",
                                                    selectedSeverity === category.id
                                                        ? "text-neutral-200"
                                                        : "text-neutral-400 hover:text-neutral-200",
                                                    // Ensure click area is above the highlight
                                                    "z-10"
                                                )}
                                                whileTap={{ scale: 0.98 }}
                                                variants={itemVariants}
                                            >
                                                <IconWrapper
                                                    icon={category.icon}
                                                    isHovered={hoveredCategory === category.id}
                                                    color={category.color}
                                                />
                                                {category.label}
                                            </motion.button>
                                        </React.Fragment>
                                    ))}
                                </motion.div>
                            </motion.div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </MotionConfig>
    );
}
