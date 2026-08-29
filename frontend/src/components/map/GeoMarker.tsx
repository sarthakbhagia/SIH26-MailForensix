import { Marker } from 'react-map-gl/maplibre';
import { getInfrastructureTokens, getSeverityHex } from '@/lib/severity';

export interface GeoMarkerProps {
  latitude: number;
  longitude: number;
  index: number;
  infrastructureType?: string;
  riskScore?: number;
  delay?: number;
  isSelected?: boolean;
  onClick?: () => void;
}

export function GeoMarker({
  latitude,
  longitude,
  index,
  infrastructureType = 'residential',
  riskScore = 0,
  isSelected = false,
  onClick,
}: GeoMarkerProps) {
  const infra = getInfrastructureTokens(infrastructureType);
  const color = (infra.category === 'tor' || infra.category === 'vpn') ? '#ff2a55' : infra.category === 'hosting' ? '#ffb020' : getSeverityHex(riskScore);

  return (
    <Marker
      latitude={latitude}
      longitude={longitude}
      anchor="center"
      onClick={(e) => {
        e.originalEvent.stopPropagation();
        onClick?.();
      }}
    >
      <div
        className="group relative flex items-center justify-center cursor-pointer transition-transform hover:scale-125"
        style={{ width: '26px', height: '26px' }}
      >
        <div
          className={`size-5 rounded-full flex items-center justify-center font-mono text-[9px] font-bold text-black shadow-md border-2 border-background ${
            isSelected ? 'ring-4 ring-primary scale-110' : ''
          }`}
          style={{ backgroundColor: color }}
        >
          #{index + 1}
        </div>
      </div>
    </Marker>
  );
}

export default GeoMarker;
