#ifndef RCATRACE_H
#define RCATRACE_H
#include "OpbSnapshotAnalyzer.h"
#include <QFileInfo>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QMap>
#include <QSet>

class RcaTrace
{
    static QJsonObject eventJson(const OpbSnapshotEvent &event)
    {
        return QJsonObject{{"event_index", QString::number(event.index)}, {"source_line", event.line},
                           {"level", event.level}, {"code", event.code}, {"description", event.description},
                           {"raw", event.rawValue}, {"decoded", event.decodedValue},
                           {"cycle", event.hasCycle ? QJsonValue(QString::number(event.cycle)) : QJsonValue()}};
    }
    static QJsonObject sourceJson(const QString &name, const QString &board)
    {
        QJsonObject result{{"file", name.isEmpty() ? QString("UNKNOWN") : name}, {"board_type", board},
                           {"end", "UNKNOWN"}, {"system", "UNKNOWN"}, {"network", "UNKNOWN"}};
        static const QRegularExpression identity("(?:ATP|IPB|OPB|SPB)[_-](H|T)[_-]?(A|B)[_-]?(G|P)(?:[_\\.]|$)",
                                                 QRegularExpression::CaseInsensitiveOption);
        const auto match = identity.match(name);
        if(match.hasMatch()) {
            result.insert("end", match.captured(1).toUpper());
            result.insert("system", match.captured(2).toUpper());
            result.insert("network", match.captured(3).toUpper());
        }
        return result;
    }
public:
    static QJsonObject Build(const QVector<OpbSnapshotEvent> &events, const OpbDiagnosticAnalyzer::Input &input)
    {
        const int maxEvents = 2000, maxBytes = 160000;
        int previousMarker = -1, lastMarker = -1, markers = 0, cycleSegments = 0;
        for(int index = 0; index < events.size(); ++index) {
            if(events[index].code == "0x0A1A") {
                ++markers;
                if(lastMarker < 0 || events[index].cycle != events[lastMarker].cycle) {
                    previousMarker = lastMarker; lastMarker = index; ++cycleSegments;
                }
            }
        }
        int desiredStart = previousMarker >= 0 ? previousMarker : 0;
        if(desiredStart <= 64) desiredStart = 0;
        int start = events.size(), bytes = 4096;
        QSet<QString> sourceNames;
        for(int index = events.size() - 1; index >= desiredStart && events.size() - start < maxEvents; --index) {
            const auto &event = events[index];
            const QString name = QFileInfo(event.sourceFile).fileName();
            int cost = QJsonDocument(eventJson(event)).toJson(QJsonDocument::Compact).size() + 32;
            if(!sourceNames.contains(name)) cost += QJsonDocument(sourceJson(name, input.boardType)).toJson(QJsonDocument::Compact).size() + 8;
            if(bytes + cost > maxBytes) break;
            bytes += cost;
            sourceNames.insert(name);
            start = index;
        }
        QJsonArray selected, sources, segments;
        QMap<QString, int> fileIndices;
        QJsonObject segment;
        for(int index = start; index < events.size(); ++index) {
            const auto &event = events[index];
            const QString name = QFileInfo(event.sourceFile).fileName();
            if(!fileIndices.contains(name)) {
                fileIndices.insert(name, sources.size());
                sources.append(sourceJson(name, input.boardType));
            }
            QJsonObject row = eventJson(event);
            row.insert("source_file", fileIndices.value(name));
            selected.append(row);
            const QJsonValue cycle = row.value("cycle");
            if(segment.isEmpty() || segment.value("cycle") != cycle) {
                if(!segment.isEmpty()) {
                    segment.insert("has_next_cycle_marker", event.code == "0x0A1A");
                    segments.append(segment);
                }
                segment = QJsonObject{{"cycle", cycle}, {"first_event_index", QString::number(event.index)},
                                      {"marker_observed", event.code == "0x0A1A"}, {"event_count", 0},
                                      {"has_next_cycle_marker", false}};
            }
            if(event.code == "0x0A1A") segment.insert("marker_observed", true);
            segment.insert("last_event_index", QString::number(event.index));
            segment.insert("event_count", segment.value("event_count").toInt() + 1);
        }
        if(!segment.isEmpty()) segments.append(segment);
        return QJsonObject{{"schema_version", "crash-log-rca-trace/1"}, {"cycle_source", "0x0A1A"},
                           {"window_policy", "latest_two_observed_cycles_with_available_preamble"},
                           {"observed_cycle_marker_count", markers}, {"sources", sources}, {"events", selected},
                           {"observed_cycle_segment_count", cycleSegments},
                           {"cycle_segments", segments}, {"total_capture_events", QString::number(events.size())},
                           {"omitted_earlier_events", start}, {"truncated", start > desiredStart},
                           {"max_events", maxEvents}, {"max_bytes", maxBytes},
                           {"cycle_assessment", "Check stage completion and health using the supplied board-specific source and log coverage"}};
    }
};
#endif
