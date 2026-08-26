import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function HeaderInspector({ headers }: { headers: Record<string, string> }) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <Card>
      <CardHeader className="py-3 px-4 border-b flex flex-row items-center justify-between cursor-pointer" onClick={() => setIsOpen(!isOpen)}>
        <CardTitle className="text-sm font-medium">Raw Headers</CardTitle>
        <Button variant="ghost" size="icon" className="h-6 w-6">
          {isOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </Button>
      </CardHeader>
      {isOpen && (
        <CardContent className="p-0">
          <pre className="p-4 bg-muted/30 text-xs overflow-x-auto whitespace-pre-wrap max-h-96 overflow-y-auto">
            {Object.entries(headers || {}).map(([key, value]) => `${key}: ${value}\n`).join('')}
          </pre>
        </CardContent>
      )}
    </Card>
  );
}
