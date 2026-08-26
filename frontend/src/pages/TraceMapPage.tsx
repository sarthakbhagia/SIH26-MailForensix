import { useState } from "react";
import { Map, Marker, Source, Layer, Popup } from "react-map-gl/maplibre";
import "maplibre-gl/dist/maplibre-gl.css";
import { Badge } from "@/components/ui/badge";

const MAP_STYLE = "https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json";

interface HopGeo {
  latitude: number;
  longitude: number;
  hostname: string;
  infrastructureType: string;
  riskScore: number;
  delay?: number;
  timestamp?: string;
}

interface EmailAnalysis {
  subject: string;
  sender: string;
  hops: HopGeo[];
}

interface TraceMapPageProps {
  analysis?: EmailAnalysis | null;
  emailId?: string;
}

export function TraceMapPage({ analysis }: TraceMapPageProps) {
  const [selectedHop, setSelectedHop] = useState<(HopGeo & { index: number }) | null>(null);

  if (!analysis || !analysis.hops || analysis.hops.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh]">
        <h1 className="text-4xl font-bold mb-4">Trace Map</h1>
        <p className="text-xl text-muted-foreground">Select an email or ingest an email to view its geo-trace path on the map.</p>
      </div>
    );
  }

  const hopMarkers = analysis.hops.map((hop, index) => ({
    ...hop,
    index,
  }));

  const geojsonLine = {
    type: "FeatureCollection" as const,
    features: [
      {
        type: "Feature" as const,
        geometry: {
          type: "LineString" as const,
          coordinates: hopMarkers.map((h) => [h.longitude, h.latitude]),
        },
        properties: {},
      },
    ],
  };

  return (
    <div className="flex flex-col h-screen w-full">
      <div className="flex border-b pb-4">
        <h1 className="text-2xl font-bold flex-1">Trace Map</h1>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <span>Subject: {analysis.subject}</span>
          <span>Sender: {analysis.sender}</span>
        </div>
      </div>

      <div className="flex h-[70vh] w-full">
        <div className="flex-1 h-full relative">
          <Map
            mapStyle={MAP_STYLE}
            initialViewState={{
              longitude: hopMarkers.length > 0 ? hopMarkers[0].longitude : 0,
              latitude: hopMarkers.length > 0 ? hopMarkers[0].latitude : 0,
              zoom: 3,
            }}
            style={{ width: "100%", height: "100%" }}
          >
            <Source type="geojson" data={geojsonLine} id="path-source">
              <Layer
                type="line"
                id="path-layer"
                paint={{
                  "line-color": "#3b82f6",
                  "line-width": 3,
                }}
                layout={{
                  "line-join": "round",
                  "line-cap": "round",
                }}
              />
            </Source>

            {hopMarkers.map((hop, index) => (
              <Marker
                key={index}
                latitude={hop.latitude}
                longitude={hop.longitude}
                anchor="bottom"
                onClick={(e) => {
                  e.originalEvent.stopPropagation();
                  setSelectedHop(hop);
                }}
              >
                <div
                  style={{
                    width: "16px",
                    height: "16px",
                    borderRadius: "50%",
                    backgroundColor:
                      hop.infrastructureType === "known_vpn" || hop.infrastructureType === "tor_exit_node"
                        ? "#ef4444"
                        : hop.infrastructureType === "aws_cloud"
                          ? "#f59e0b"
                          : "#22c55e",
                    border: "2px solid white",
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
                <div className="min-w-[200px] p-2 text-foreground">
                  <div className="font-bold text-sm mb-2 border-b pb-1">
                    Hop #{selectedHop.index + 1}
                  </div>
                  <div className="text-xs mb-1">
                    <strong>IP:</strong> {selectedHop.hostname || "N/A"}
                  </div>
                  <div className="text-xs mb-1">
                    <strong>Delay:</strong> {selectedHop.delay !== undefined ? `${selectedHop.delay}s` : "N/A"}
                  </div>
                  <div className="flex items-center gap-1 mb-1">
                    <strong className="text-xs">Type:</strong>
                    <Badge variant="outline" className="text-[10px] px-1 py-0">
                      {selectedHop.infrastructureType}
                    </Badge>
                  </div>
                  <div className="text-xs">
                    <strong>Risk Score:</strong> {selectedHop.riskScore}/100
                  </div>
                </div>
              </Popup>
            )}
          </Map>
        </div>

        <div className="w-64 h-[70vh] border-l border-gray-700 flex flex-col">
          <div className="p-3 border-b border-gray-700">
            <h3 className="font-medium">Path Summary</h3>
          </div>
          <div className="flex-1 overflow-y-auto">
            <div className="p-2 text-xs text-gray-400">Total hops: {hopMarkers.length}</div>
            {hopMarkers.map((hop, i) => (
              <div
                key={i}
                onClick={() => setSelectedHop(hop)}
                className={`p-2 cursor-pointer ${selectedHop?.index === i ? "bg-gray-800" : ""} mb-1 text-xs`}
              >
                {hop.infrastructureType} {hop.hostname} ({hop.delay ? `${hop.delay}s` : ""})
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default TraceMapPage;