package com.ccp.repository;

import com.ccp.model.Session;
import com.ccp.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface SessionRepository extends JpaRepository<Session, Long> {

    Optional<Session> findBySessionId(String sessionId);

    List<Session> findByUserAndActiveTrue(User user);

    @Modifying
    @Query("UPDATE Session s SET s.active = false WHERE s.user = ?1 AND s.sessionId <> ?2")
    void deactivateOtherSessions(User user, String currentSessionId);

    @Modifying
    @Query("UPDATE Session s SET s.active = false WHERE s.expiresAt < ?1")
    void deactivateExpiredSessions(LocalDateTime now);

    @Modifying
    @Query("DELETE FROM Session s WHERE s.expiresAt < ?1")
    void deleteExpiredSessions(LocalDateTime before);
}