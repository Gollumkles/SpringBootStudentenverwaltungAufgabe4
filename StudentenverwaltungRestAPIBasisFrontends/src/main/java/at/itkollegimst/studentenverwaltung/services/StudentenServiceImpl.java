package at.itkollegimst.studentenverwaltung.services;

import at.itkollegimst.studentenverwaltung.domain.Student;
import at.itkollegimst.studentenverwaltung.exceptions.StudentNichtGefunden;
import at.itkollegimst.studentenverwaltung.repositories.DbZugriffStudenten;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class StudentenServiceImpl implements StudentenService {

    private DbZugriffStudenten dbZugriffStudenten;

    public StudentenServiceImpl(DbZugriffStudenten dbZugriffStudenten) {
        this.dbZugriffStudenten = dbZugriffStudenten;
    }

    @Override
    public List<Student> alleStudenten() {
        return this.dbZugriffStudenten.alleStudenten();
    }

    @Override
    public Student studentEinfuegen(Student student) {
        return this.dbZugriffStudenten.studentSpeichern(student);
    }

    @Override
    public Student studentUpdaten(Student student) throws StudentNichtGefunden {
        Student studentAusDb = this.dbZugriffStudenten.studentMitId(student.getId());
        studentAusDb.setName(student.getName());
        studentAusDb.setPlz(student.getPlz());
        return this.dbZugriffStudenten.studentSpeichern(studentAusDb);
    }

    @Override
    public Student studentMitId(Long id) throws StudentNichtGefunden {
        return this.dbZugriffStudenten.studentMitId(id);
    }

    @Override
    public List<Student> alleStudentenMitPlz(String plz) {
        return this.dbZugriffStudenten.alleStudentenAusDemOrt(plz);
    }

    @Override
    public Student studentLoeschenMitId(Long id) throws StudentNichtGefunden {
        return this.dbZugriffStudenten.studentLoeschenMitId(id);
    }
}
