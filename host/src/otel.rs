use opentelemetry::{global, trace::TracerProvider, KeyValue};
use opentelemetry_sdk::{
    runtime::Tokio,
    trace::{self, RandomIdGenerator, Sampler},
    Resource,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize OpenTelemetry tracing + structured logging.
///
/// Environment knobs (standard):
/// - OTEL_EXPORTER_OTLP_ENDPOINT (e.g. http://localhost:4317)
/// - OTEL_EXPORTER_OTLP_HEADERS / OTEL_EXPORTER_OTLP_TIMEOUT (optional)
/// - OTEL_SERVICE_NAME (optional)
///
/// This is intentionally minimal for v1 (demo + investor-ready story).
pub fn init() {
    // Resource attributes
    let service_name = std::env::var("OTEL_SERVICE_NAME")
        .unwrap_or_else(|_| "ephemeralml-kms-proxy-host".to_string());
    let resource = Resource::new(vec![KeyValue::new("service.name", service_name)]);

    // Build OTLP SpanExporter (tonic). Uses standard OTEL_* env vars.
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
        .expect("otel span exporter build failed");

    // Tracer provider (batch exporter on Tokio runtime)
    let provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, Tokio)
        .with_config(
            trace::Config::default()
                .with_resource(resource)
                .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(0.1))))
                .with_id_generator(RandomIdGenerator::default()),
        )
        .build();

    let tracer = provider.tracer("ephemeralml");
    global::set_tracer_provider(provider);

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // JSON logs to stdout (CloudWatch/journal friendly)
    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true);

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();
}

pub fn shutdown() {
    global::shutdown_tracer_provider();
}
