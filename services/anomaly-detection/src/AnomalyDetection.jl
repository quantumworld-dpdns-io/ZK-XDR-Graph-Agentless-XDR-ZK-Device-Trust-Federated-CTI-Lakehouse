module AnomalyDetection

using HTTP
using JSON
using Statistics
using Distributions

export detect_anomalies, compute_baseline, is_anomalous

struct EventMetric
    timestamp::String
    source::String
    event_type::String
    count::Int
    severity_score::Float64
end

struct AnomalyResult
    is_anomaly::Bool
    score::Float64
    threshold::Float64
    deviation::Float64
    description::String
end

function compute_baseline(metrics::Vector{EventMetric}; window::Int=100)::Dict{String, Float64}
    baselines = Dict{String, Float64}()
    
    counts = [m.count for m in metrics]
    if length(counts) < 2
        return baselines
    end
    
    baselines["mean_count"] = mean(counts)
    baselines["std_count"] = std(counts)
    baselines["median_count"] = median(counts)
    
    severity_scores = [m.severity_score for m in metrics]
    baselines["mean_severity"] = mean(severity_scores)
    baselines["std_severity"] = std(severity_scores)
    
    baselines
end

function is_anomalous(value::Float64, mean_val::Float64, std_val::Float64; threshold::Float64=3.0)::AnomalyResult
    if std_val < 1e-10
        return AnomalyResult(false, 0.0, threshold, 0.0, "Insufficient variance for detection")
    end
    
    z_score = abs(value - mean_val) / std_val
    deviation = value - mean_val
    
    is_anom = z_score > threshold
    
    description = if is_anom
        if deviation > 0
            "Value $(round(value, digits=2)) is $(round(z_score, digits=2)) standard deviations above mean"
        else
            "Value $(round(value, digits=2)) is $(round(z_score, digits=2)) standard deviations below mean"
        end
    else
        "Value $(round(value, digits=2)) within normal range"
    end
    
    AnomalyResult(is_anom, z_score, threshold, deviation, description)
end

function detect_anomalies(events::Vector{Dict{Any, Any}})::Vector{AnomalyResult}
    results = AnomalyResult[]
    
    if length(events) < 10
        push!(results, AnomalyResult(false, 0.0, 3.0, 0.0, "Insufficient data for anomaly detection"))
        return results
    end
    
    # Compute per-source statistics
    source_events = Dict{String, Vector{Int}}()
    for event in events
        source = get(event, "source", "unknown")
        if !haskey(source_events, source)
            source_events[source] = Int[]
        end
        push!(source_events[source], get(event, "risk_score", 0))
    end
    
    # Check each source for anomalies
    for (source, scores) in source_events
        if length(scores) >= 5
            mean_score = mean(scores)
            std_score = std(scores)
            
            # Check the most recent score
            latest = scores[end]
            result = is_anomalous(Float64(latest), mean_score, std_score)
            push!(results, result)
            
            # Check for sudden spike
            if length(scores) >= 3
                recent_mean = mean(scores[end-2:end])
                overall_mean = mean(scores)
                if recent_mean > overall_mean * 2
                    push!(results, AnomalyResult(
                        true, 
                        recent_mean / max(overall_mean, 0.01), 
                        2.0, 
                        recent_mean - overall_mean,
                        "Spike detected in $source: recent avg $(round(recent_mean, digits=1)) vs baseline $(round(overall_mean, digits=1))"
                    ))
                end
            end
        end
    end
    
    # Check for volume anomalies
    timestamps = [get(e, "timestamp", "") for e in events]
    unique_timestamps = unique(timestamps)
    if length(unique_timestamps) > 1
        # Group by minute
        minute_counts = Dict{String, Int}()
        for ts in timestamps
            minute_key = length(ts) >= 16 ? ts[1:16] : ts
            minute_counts[minute_key] = get(minute_counts, minute_key, 0) + 1
        end
        
        counts = collect(values(minute_counts))
        if length(counts) >= 3
            mean_count = mean(counts)
            std_count = std(counts)
            latest_count = counts[end]
            
            if std_count > 0
                volume_result = is_anomalous(Float64(latest_count), mean_count, std_count)
                push!(results, volume_result)
            end
        end
    end
    
    results
end

function run_http_server()
    println("Starting Anomaly Detection service on port 8086...")
    
    HTTP.serve("0.0.0.0", 8086) do request
        if request.method == "POST" && request.target == "/api/v1/detect"
            try
                body = JSON.parse(String(request.body))
                events = get(body, "events", [])
                
                results = detect_anomalies(events)
                
                anomalies = [r for r in results if r.is_anomaly]
                
                response = Dict(
                    "total_events" => length(events),
                    "anomalies_found" => length(anomalies),
                    "results" => [
                        Dict(
                            "is_anomaly" => r.is_anomaly,
                            "score" => round(r.score, digits=3),
                            "threshold" => r.threshold,
                            "deviation" => round(r.deviation, digits=2),
                            "description" => r.description
                        ) for r in results
                    ]
                )
                
                HTTP.Response(200, ["Content-Type" => "application/json"], body=JSON.json(response))
            catch e
                HTTP.Response(400, body=JSON.json(Dict("error" => string(e))))
            end
        elseif request.method == "GET" && request.target == "/api/v1/health"
            HTTP.Response(200, body=JSON.json(Dict("status" => "healthy", "service" => "anomaly-detection")))
        else
            HTTP.Response(404, body="Not found")
        end
    end
end

end # module

if abspath(PROGRAM_FILE) == @__FILE__
    AnomalyDetection.run_http_server()
end
