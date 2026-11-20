package dev.scanqueue.chaos;

import java.sql.Array;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** One JDBC connection, synchronized. Each harness thread gets its own instance. */
final class Db implements AutoCloseable {

    private final String url;
    private final String user;
    private final String password;
    private Connection c;

    Db(String url, String user, String password) {
        this.url = url;
        this.user = user;
        this.password = password;
    }

    private Connection conn() throws SQLException {
        if (c == null || c.isClosed() || !c.isValid(2)) {
            c = DriverManager.getConnection(url, user, password);
            c.setAutoCommit(true);
        }
        return c;
    }

    synchronized List<Map<String, Object>> rows(String sql, Object... args) {
        try (PreparedStatement ps = prepare(sql, args); ResultSet rs = ps.executeQuery()) {
            ResultSetMetaData md = rs.getMetaData();
            List<Map<String, Object>> out = new ArrayList<>();
            while (rs.next()) {
                Map<String, Object> row = new LinkedHashMap<>();
                for (int i = 1; i <= md.getColumnCount(); i++) {
                    row.put(md.getColumnLabel(i), rs.getObject(i));
                }
                out.add(row);
            }
            return out;
        } catch (SQLException e) {
            throw new IllegalStateException(sql, e);
        }
    }

    synchronized List<String> strings(String sql, Object... args) {
        List<String> out = new ArrayList<>();
        for (Map<String, Object> r : rows(sql, args)) {
            Object v = r.values().iterator().next();
            out.add(v == null ? null : v.toString());
        }
        return out;
    }

    synchronized double num(String sql, Object... args) {
        Object v = rows(sql, args).get(0).values().iterator().next();
        return v == null ? Double.NaN : ((Number) v).doubleValue();
    }

    synchronized long count(String sql, Object... args) {
        return (long) num(sql, args);
    }

    synchronized void exec(String sql) {
        try (var st = conn().createStatement()) {
            st.execute(sql);
        } catch (SQLException e) {
            throw new IllegalStateException(sql, e);
        }
    }

    /** DB clock, epoch millis. Every timestamp the harness records comes from here. */
    double nowMillis() {
        return num("SELECT extract(epoch FROM clock_timestamp()) * 1000");
    }

    Array uuidArray(List<UUID> ids) {
        try {
            return conn().createArrayOf("uuid", ids.toArray());
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    private PreparedStatement prepare(String sql, Object... args) throws SQLException {
        PreparedStatement ps = conn().prepareStatement(sql);
        for (int i = 0; i < args.length; i++) {
            ps.setObject(i + 1, args[i]);
        }
        return ps;
    }

    @Override
    public synchronized void close() {
        try {
            if (c != null) {
                c.close();
            }
        } catch (SQLException ignored) {
            // closing anyway
        }
    }
}
