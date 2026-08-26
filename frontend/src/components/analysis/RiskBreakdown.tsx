import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from "recharts";

interface RiskFactor {
  name: string;
  score: number;
  percentage: number;
  color: string;
}

interface RiskBreakdownProps {
  overallScore: number;
  factors?: RiskFactor[];
}

export function RiskBreakdown({ overallScore, factors }: RiskBreakdownProps) {
  const defaultFactors: RiskFactor[] = [
    { name: "NLP Threat Score", score: 72, percentage: 35, color: "#3b82f6" },
    { name: "Auth Confidence", score: 85, percentage: 25, color: "#10b981" },
    { name: "IP Reputation", score: 60, percentage: 20, color: "#f59e0b" },
    { name: "Link Risk", score: 95, percentage: 10, color: "#8b5cf6" },
    { name: "Attachment Risk", score: 30, percentage: 10, color: "#ec4899" },
  ];

  const renderedFactors = factors || defaultFactors;

  const getColor = (factor: RiskFactor) => {
    if (factor.score >= 75) return "#ef4444";
    if (factor.score >= 50) return "#f59e0b";
    return "#22c55e";
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Overall Risk Score: {overallScore}/100{" "}
          {overallScore >= 75 ? "🔴 HIGH" : overallScore >= 50 ? "🟡 MEDIUM" : "🟢 LOW"}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={renderedFactors}
              margin={{ top: 20, right: 30, left: 0, bottom: 20 }}
            >
              <XAxis dataKey="name" height={30} tick={{ fontSize: 12 }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} />
              <Tooltip />
              <Legend verticalAlign="bottom" height={36} />
              {renderedFactors.map((factor, index) => (
                <Bar
                  key={index}
                  dataKey="score"
                  name={factor.name}
                  fill={getColor(factor)}
                  barSize={24}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}