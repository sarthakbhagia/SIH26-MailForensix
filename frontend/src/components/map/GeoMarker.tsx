import { Marker } from "react-map-gl/maplibre";

interface GeoMarkerProps {
  latitude: number;
  longitude: number;
  index: number;
  infrastructureType: "residential" | "corporate" | "aws_cloud" | "known_vpn" | "tor_exit_node" | "proxy" | string;
  riskScore: number;
  delay?: number;
}

export function GeoMarker({ latitude, longitude, infrastructureType, riskScore }: GeoMarkerProps) {
  const size = riskScore > 70 ? 12 : riskScore > 40 ? 8 : 6;
  const colorMap: Record<string, string> = {
    residential: "green",
    corporate: "orange",
    aws_cloud: "orange",
    known_vpn: "red",
    tor_exit_node: "red",
    proxy: "red",
  };

  const color = colorMap[infrastructureType] || "gray";

  return (
    <Marker
      latitude={latitude}
      longitude={longitude}
      anchor="bottom"
    >

      <div
        style={{
          width: `${size * 2}px`,
          height: `${size * 2}px`,
          borderRadius: "50%",
          backgroundColor: color,
          border: "2px solid white",
          boxShadow: "0 2px 6px rgba(0,0,0,0.3)",
        }}
      />
      <div className="text-center text-xs mt-1" style={{ color: color }}>
        {riskScore}
      </div>
    </Marker>
  );
}