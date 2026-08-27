import React from 'react';
import { cn } from '@/lib/utils';

export interface TraceMapProps extends React.HTMLAttributes<HTMLDivElement> {
  latitude?: number | null;
  longitude?: number | null;
  locationText?: string;
  ip?: string;
  provider?: string;
  infrastructure?: string;
  confidence?: number;
}

const LANDMASS = [
  "M 118 78 L 168 62 L 214 66 L 236 92 L 224 120 L 196 138 L 168 132 L 150 150 L 132 138 L 120 108 Z",
  "M 196 176 L 222 168 L 236 196 L 252 232 L 240 276 L 216 300 L 200 268 L 194 224 Z",
  "M 330 66 L 372 56 L 412 64 L 430 84 L 404 104 L 372 100 L 342 92 Z",
  "M 340 110 L 386 104 L 402 132 L 412 178 L 392 226 L 366 244 L 348 206 L 336 156 Z",
  "M 440 60 L 520 46 L 600 58 L 636 84 L 612 118 L 560 128 L 500 118 L 456 96 Z",
  "M 468 128 L 512 126 L 528 160 L 506 186 L 482 166 Z",
  "M 596 236 L 646 228 L 672 254 L 656 288 L 616 284 L 594 262 Z",
];

function projectCoordinates(lat: number, lon: number): { x: number; y: number } {
  return {
    x: ((lon + 180) / 360) * 720,
    y: ((90 - lat) / 180) * 360,
  };
}

export function TraceMap({
  latitude,
  longitude,
  locationText,
  ip,
  provider,
  infrastructure,
  confidence = 85,
  className,
  ...props
}: TraceMapProps) {
  const hasCoordinates = latitude != null && longitude != null && !isNaN(latitude) && !isNaN(longitude);
  const point = hasCoordinates ? projectCoordinates(latitude!, longitude!) : null;

  return (
    <div className={cn('panel grid-bg relative overflow-hidden', className)} {...props}>
      <svg viewBox="0 0 720 360" className="h-auto w-full block select-none">
        {/* Render Landmasses */}
        {LANDMASS.map((d, i) => (
          <path
            key={i}
            d={d}
            fill="var(--surface-2)"
            stroke="var(--border)"
            strokeWidth="1"
            strokeLinejoin="round"
          />
        ))}

        {/* Render Radar Ping & Crosshairs if point exists */}
        {point && (
          <g>
            {/* Coordinate Crosshairs */}
            <line
              x1={point.x}
              y1={0}
              x2={point.x}
              y2={360}
              stroke="var(--primary)"
              strokeOpacity="0.35"
              strokeDasharray="4 6"
            />
            <line
              x1={0}
              y1={point.y}
              x2={720}
              y2={point.y}
              stroke="var(--primary)"
              strokeOpacity="0.35"
              strokeDasharray="4 6"
            />

            {/* Ambient radar glow */}
            <circle cx={point.x} cy={point.y} r="28" fill="var(--critical)" fillOpacity="0.12" />

            {/* Pulsing Radar Ring */}
            <circle cx={point.x} cy={point.y} r="14" fill="var(--critical)" fillOpacity="0.25">
              <animate attributeName="r" values="10;24;10" dur="2.4s" repeatCount="indefinite" />
              <animate
                attributeName="fill-opacity"
                values="0.35;0.02;0.35"
                dur="2.4s"
                repeatCount="indefinite"
              />
            </circle>

            {/* Center Origin Dot */}
            <circle cx={point.x} cy={point.y} r="4.5" fill="var(--critical)" stroke="#FFFFFF" strokeWidth="1" />
          </g>
        )}
      </svg>

      {/* Top-Left Telemetry Overlay */}
      <div className="absolute left-4 top-4 space-y-1 pointer-events-none">
        <p className="label-mono">estimated origin</p>
        <p className="font-mono text-sm font-semibold text-foreground">
          {locationText || (hasCoordinates ? `${latitude?.toFixed(2)}°, ${longitude?.toFixed(2)}°` : 'Undetermined')}
        </p>
        <p className="font-mono text-xs text-muted-foreground">
          {ip ? <span className="text-primary">{ip}</span> : 'no public IP'}
          {provider && <span> · {provider}</span>}
          {infrastructure && <span className="uppercase text-[10px]"> ({infrastructure})</span>}
        </p>
      </div>

      {/* Bottom-Right Confidence Badge */}
      <div className="absolute bottom-4 right-4 rounded-md border border-border bg-background/80 px-3 py-2 text-right backdrop-blur shadow-sm pointer-events-none">
        <p className="label-mono">geo confidence</p>
        <p className="font-mono text-lg font-bold text-primary">{confidence}%</p>
      </div>
    </div>
  );
}

export default TraceMap;
