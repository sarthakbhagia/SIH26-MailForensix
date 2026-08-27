import { RelayHop } from '@/types/analysis';
import { RelayHopNode } from '@/components/forensics/RelayHopNode';
import { Route, Layers } from 'lucide-react';

export interface RelayPathViewerProps {
  hops: RelayHop[];
}

export function RelayPathViewer({ hops }: RelayPathViewerProps) {
  if (!hops || hops.length === 0) {
    return (
      <div className="panel p-8 text-center text-muted-foreground">
        <Route className="size-8 mx-auto opacity-40 mb-2" />
        <p className="text-sm font-medium text-foreground">No relay path data recorded</p>
        <p className="text-xs text-muted-foreground mt-0.5">
          Header transmission trace was not available in this message.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
            <Layers className="size-4 text-primary" />
            Transmission Hop Sequence ({hops.length} {hops.length === 1 ? 'Hop' : 'Hops'})
          </h3>
          <p className="label-mono text-[10px] mt-0.5">CHRONOLOGICAL MTA RELAY ROUTING LEDGER</p>
        </div>
      </div>

      <div className="space-y-3">
        {hops.map((hop, index) => (
          <RelayHopNode
            key={index}
            hop={hop}
            index={index}
            totalHops={hops.length}
            isOrigin={index === 0}
            isDestination={index === hops.length - 1}
          />
        ))}
      </div>
    </div>
  );
}

export default RelayPathViewer;