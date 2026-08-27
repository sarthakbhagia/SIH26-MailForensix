import { useState } from "react";
import { Map, Marker, Source, Layer, Popup } from "react-map-gl/maplibre";
import "maplibre-gl/dist/maplibre-gl.css";

const MAP_STYLE = "https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json";

interface HopCoord {
  latitude: number;
  longitude: number;
  index: number;
  infrastructureType: string;
  riskScore: number;
  delay?: number;
  hostname?: string;
}

interface TraceMapProps {
  hops: HopCoord[];
  onHopSelect?: (index: number) => void;
}

export function TraceMap({ hops, onHopSelect }: TraceMapProps) {
  const [selectedHop, setSelectedHop] = useState<HopCoord | null>(null);

  const geojsonLine = {
    type: "FeatureCollection" as const,
    features: [
      {
        type: "Feature" as const,
        geometry: {
          type: "LineString" as const,
          coordinates: hops.map((h) => [h.longitude, h.latitude]),
        },
        properties: {},
      },
    ],
  };

  const lineColor =
    hops.length > 0 && hops[hops.length - 1].infrastructureType === "known_vpn"
      ? "#ff3366"
      : "#00e5ff";

  return (
    <div className="w-full h-full relative">
      <Map
        mapStyle={MAP_STYLE}
        initialViewState={{
          longitude: hops.length > 0 ? hops[0].longitude : 0,
          latitude: hops.length > 0 ? hops[0].latitude : 0,
          zoom: 2,
        }}
        style={{ width: "100%", height: "100%" }}
      >
        <Source type="geojson" data={geojsonLine} id="path-source">
          <Layer
            type="line"
            id="path-layer"
            paint={{
              "line-color": lineColor,
              "line-width": 3,
            }}
            layout={{
              "line-join": "round",
              "line-cap": "round",
            }}
          />
        </Source>

        {hops.map((hop, index) => (
          <Marker
            key={index}
            latitude={hop.latitude}
            longitude={hop.longitude}
            anchor="bottom"
            onClick={(e) => {
              e.originalEvent.stopPropagation();
              setSelectedHop(hop);
              onHopSelect?.(index);
            }}
          >
            <div
              style={{
                width: "16px",
                height: "16px",
                borderRadius: "50%",
                backgroundColor: hop.riskScore > 70 ? "#ff3366" : hop.riskScore > 40 ? "#ffb020" : "#00e5ff",
                border: "2px solid rgba(255, 255, 255, 0.8)",
                cursor: "pointer",
              }}
            />
          </Marker>
        ))}

        {selectedHop && (
          <Popup
            latitude={selectedHop.latitude}
            longitude={selectedHop.longitude}
            anchor="bottom"
            onClose={() => setSelectedHop(null)}
          >
            <div className="min-w-[180px] p-2 text-foreground font-mono text-xs panel">
              <div className="font-bold text-sm mb-1 text-primary">
                Hop #{selectedHop.index + 1}
              </div>
              <div>
                <strong className="text-muted-foreground">IP:</strong> {selectedHop.hostname || "N/A"}
              </div>
              <div>
                <strong className="text-muted-foreground">Type:</strong> {selectedHop.infrastructureType}
              </div>
              {selectedHop.delay !== undefined && (
                <div>
                  <strong className="text-muted-foreground">Delay:</strong> {selectedHop.delay}s
                </div>
              )}
              <div>
                <strong className="text-muted-foreground">Score:</strong> {selectedHop.riskScore}
              </div>
            </div>
          </Popup>
        )}
      </Map>
    </div>
  );
}