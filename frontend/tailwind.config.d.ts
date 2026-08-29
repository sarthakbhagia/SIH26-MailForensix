declare const config: {
    darkMode: ["class"];
    content: string[];
    prefix: string;
    theme: {
        container: {
            center: true;
            padding: string;
            screens: {
                '2xl': string;
            };
        };
        extend: {
            fontFamily: {
                sans: [string, string, string, string];
                mono: [string, string, string, string];
            };
            colors: {
                border: {
                    DEFAULT: string;
                    subtle: string;
                    strong: string;
                };
                input: string;
                ring: string;
                background: string;
                foreground: {
                    DEFAULT: string;
                    secondary: string;
                };
                surface: {
                    DEFAULT: string;
                    2: string;
                    3: string;
                    overlay: string;
                };
                grid: string;
                primary: {
                    DEFAULT: string;
                    foreground: string;
                };
                secondary: {
                    DEFAULT: string;
                    foreground: string;
                };
                destructive: {
                    DEFAULT: string;
                    foreground: string;
                };
                muted: {
                    DEFAULT: string;
                    foreground: string;
                };
                accent: {
                    DEFAULT: string;
                    foreground: string;
                };
                popover: {
                    DEFAULT: string;
                    foreground: string;
                };
                card: {
                    DEFAULT: string;
                    foreground: string;
                };
                critical: {
                    DEFAULT: string;
                    foreground: string;
                };
                high: {
                    DEFAULT: string;
                    foreground: string;
                };
                medium: {
                    DEFAULT: string;
                    foreground: string;
                };
                low: {
                    DEFAULT: string;
                    foreground: string;
                };
                clean: {
                    DEFAULT: string;
                    foreground: string;
                };
                severity: {
                    critical: string;
                    high: string;
                    medium: string;
                    low: string;
                    clean: string;
                };
            };
            boxShadow: {
                panel: string;
                glow: string;
            };
            borderRadius: {
                lg: string;
                md: string;
                sm: string;
            };
            keyframes: {
                'accordion-down': {
                    from: {
                        height: string;
                    };
                    to: {
                        height: string;
                    };
                };
                'accordion-up': {
                    from: {
                        height: string;
                    };
                    to: {
                        height: string;
                    };
                };
            };
            animation: {
                'accordion-down': string;
                'accordion-up': string;
            };
        };
    };
    plugins: any[];
};
export default config;
