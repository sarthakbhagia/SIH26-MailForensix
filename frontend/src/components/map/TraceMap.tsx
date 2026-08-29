import { useState, useMemo, useRef, useEffect } from 'react';
import { Map, Marker, Source, Layer, Popup, NavigationControl, MapRef } from 'react-map-gl/maplibre';
import 'maplibre-gl/dist/maplibre-gl.css';
import {
  Globe,
  RotateCcw,
} from 'lucide-react';
import { getSeverityHex, getInfrastructureTokens } from '@/lib/severity';
import { cn } from '@/lib/utils';

export const MAP_STYLE = 'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json';

export interface HopGeoItem {
  index: number;
  hop_number?: number;
  latitude: number;
  longitude: number;
  ip: string;
  country?: string;
  country_code?: string;
  city?: string;
  region?: string;
  isp?: string;
  asn?: string;
  org?: string;
  infrastructureType?: string;
  riskScore?: number;
  delay?: number;
  timestamp?: string;
  from_host?: string;
  by_host?: string;
  hostname?: string;
}

export interface TraceMapProps {
  hops: HopGeoItem[];
  selectedHopIndex?: number | null;
  onHopSelect?: (index: number) => void;
  className?: string;
  showControls?: boolean;
}

export function TraceMap({
  hops,
  selectedHopIndex = null,
  onHopSelect,
  className,
  showControls = true,
}: TraceMapProps) {
  const mapRef = useRef<MapRef>(null);
  const [activeHop, setActiveHop] = useState<HopGeoItem | null>(null);

  // Sync with prop-selected hop
  useEffect(() => {
    if (selectedHopIndex !== null && selectedHopIndex !== undefined && hops[selectedHopIndex]) {
      const hop = hops[selectedHopIndex];
      setActiveHop(hop);
      if (mapRef.current && hop.latitude && hop.longitude) {
        mapRef.current.flyTo({
          center: [hop.longitude, hop.latitude],
          zoom: Math.max(3.5, mapRef.current.getZoom()),
          duration: 900,
        });
      }
    } else if (selectedHopIndex === null) {
      setActiveHop(null);
    }
  }, [selectedHopIndex, hops]);

  // Valid coordinate hops only
  const validHops = useMemo(() => {
    return hops.filter((h) => h.latitude != null && h.longitude != null && !isNaN(h.latitude) && !isNaN(h.longitude));
  }, [hops]);

  // Compute flight line GeoJSON
  const geojsonLine = useMemo(() => {
    return {
      type: 'FeatureCollection' as const,
      features: [
        {
          type: 'Feature' as const,
          geometry: {
            type: 'LineString' as const,
            coordinates: validHops.map((h) => [h.longitude, h.latitude]),
          },
          properties: {},
        },
      ],
    };
  }, [validHops]);

  // Fit all coordinates to viewport
  const handleFitBounds = () => {
    if (!mapRef.current || validHops.length === 0) return;

    if (validHops.length === 1) {
      mapRef.current.flyTo({
        center: [validHops[0].longitude, validHops[0].latitude],
        zoom: 3.5,
        duration: 800,
      });
      return;
    }

    let minLon = validHops[0].longitude;
    let maxLon = validHops[0].longitude;
    let minLat = validHops[0].latitude;
    let maxLat = validHops[0].latitude;

    validHops.forEach((h) => {
      if (h.longitude < minLon) minLon = h.longitude;
      if (h.longitude > maxLon) maxLon = h.longitude;
      if (h.latitude < minLat) minLat = h.latitude;
      if (h.latitude > maxLat) maxLat = h.latitude;
    });

    mapRef.current.fitBounds(
      [
        [minLon - 5, minLat - 5],
        [maxLon + 5, maxLat + 5],
      ],
      { padding: 40, duration: 800 }
    );
  };

  const getMarkerColor = (hop: HopGeoItem) => {
    if (hop.infrastructureType) {
      const infra = getInfrastructureTokens(hop.infrastructureType);
      if (infra.category === 'tor' || infra.category === 'vpn') return '#ff2a55';
      if (infra.category === 'hosting') return '#ffb020';
    }
    return getSeverityHex(hop.riskScore || 15);
  };

  return (
    <div className={cn('w-full h-full relative overflow-hidden bg-surface select-none', className)}>
      {validHops.length === 0 ? (
        <div className="w-full h-full flex flex-col items-center justify-center p-8 text-center text-muted-foreground">
          <Globe className="size-10 opacity-30 mb-2.5 text-primary" />
          <h3 className="text-sm font-semibold text-foreground">No Geographic Coordinates Available</h3>
          <p className="text-xs text-muted-foreground max-w-xs mt-0.5">
            Transmission hops in this message contain internal private IPs or unresolvable gateway coordinates.
          </p>
        </div>
      ) : (
        <Map
          ref={mapRef}
          mapStyle={MAP_STYLE}
          initialViewState={{
            longitude: validHops.length > 0 ? validHops[0].longitude : 0,
            latitude: validHops.length > 0 ? validHops[0].latitude : 20,
            zoom: 1.8,
          }}
          style={{ width: '100%', height: '100%' }}
        >
          {showControls && (
            <>
              <NavigationControl position="top-right" showCompass={false} />
              <div className="absolute top-20 right-2.5 flex flex-col gap-1 z-10">
                <button
                  onClick={handleFitBounds}
                  className="p-1.5 rounded bg-surface-2 hover:bg-surface-3 border border-border text-muted-foreground hover:text-foreground transition-colors shadow-md"
                  title="Fit route to map bounds"
                >
                  <RotateCcw className="size-3.5" />
                </button>
              </div>
            </>
          )}

          {/* Flight Path GeoJSON Layer */}
          <Source type="geojson" data={geojsonLine} id="path-source">
            <Layer
              type="line"
              id="path-layer"
              paint={{
                'line-color': '#00e5ff',
                'line-width': 2.5,
                'line-opacity': 0.85,
                'line-dasharray': [3, 1.5],
              }}
              layout={{
                'line-join': 'round',
                'line-cap': 'round',
              }}
            />
          </Source>

          {/* Hop Markers */}
          {validHops.map((hop, idx) => {
            const markerColor = getMarkerColor(hop);
            const isSelected = activeHop?.index === hop.index;
            const isOrigin = idx === 0;
            const isDestination = idx === validHops.length - 1;

            return (
              <Marker
                key={`hop-${hop.index}-${idx}`}
                latitude={hop.latitude}
                longitude={hop.longitude}
                anchor="center"
                onClick={(e) => {
                  e.originalEvent.stopPropagation();
                  setActiveHop(hop);
                  onHopSelect?.(hop.index);
                }}
              >
                <div
                  className="group relative flex items-center justify-center cursor-pointer transition-transform hover:scale-125"
                  style={{ width: '28px', height: '28px' }}
                >
                  <div
                    className={cn(
                      'size-6 rounded-full flex items-center justify-center font-mono text-[10px] font-bold text-black shadow-lg border-2 border-background transition-all',
                      isSelected ? 'ring-4 ring-primary scale-110' : ''
                    )}
                    style={{
                      backgroundColor: markerColor,
                    }}
                  >
                    {isOrigin ? '1' : isDestination ? `${validHops.length}` : `${idx + 1}`}
                  </div>
                </div>
              </Marker>
            );
          })}

          {/* Selected Hop Popover */}
          {activeHop && (
            <Popup
              latitude={activeHop.latitude}
              longitude={activeHop.longitude}
              anchor="bottom"
              onClose={() => setActiveHop(null)}
              closeButton={true}
              className="z-50"
            >
              <div className="min-w-[200px] p-2.5 text-foreground space-y-1.5 panel shadow-2xl">
                <div className="flex items-center justify-between border-b border-border/60 pb-1">
                  <span className="label-mono font-bold text-xs">
                    Hop #{activeHop.index + 1}
                  </span>
                  <span
                    className="font-mono text-[9px] px-1 py-0.2 rounded border uppercase font-bold"
                    style={{
                      borderColor: getMarkerColor(activeHop),
                      color: getMarkerColor(activeHop),
                    }}
                  >
                    {activeHop.infrastructureType || 'RELAY'}
                  </span>
                </div>

                <div className="font-mono text-xs">
                  <span className="text-muted-foreground">IP: </span>
                  <span className="font-bold text-primary">{activeHop.ip}</span>
                </div>

                <div className="text-[11px] font-mono">
                  <span className="text-muted-foreground">Location: </span>
                  <span className="text-foreground">
                    {activeHop.city ? `${activeHop.city}, ` : ''}{activeHop.country || 'Unknown'}
                  </span>
                </div>

                {(activeHop.org || activeHop.isp) && (
                  <div className="text-[11px] font-mono truncate text-muted-foreground">
                    <span>Org: </span>
                    <span className="text-foreground">{activeHop.org || activeHop.isp}</span>
                  </div>
                )}

                {activeHop.delay !== undefined && (
                  <div className="text-[11px] font-mono text-muted-foreground">
                    <span>Delay: </span>
                    <span className="text-foreground">+{activeHop.delay.toFixed(1)}s</span>
                  </div>
                )}
              </div>
            </Popup>
          )}
        </Map>
      )}
    </div>
  );
}

export default TraceMap;
