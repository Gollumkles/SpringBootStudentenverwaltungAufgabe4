package at.itkollegimst.studentenverwaltung.services;

import at.itkollegimst.studentenverwaltung.domain.Student;
import at.itkollegimst.studentenverwaltung.exceptions.StudentNichtGefunden;

import java.util.List;

public interface StudentenService {
    List<Student> alleStudenten();
    Student studentEinfuegen(Student student);
    Student studentUpdaten(Student student) throws StudentNichtGefunden;
    Student studentMitId(Long id) throws StudentNichtGefunden;
    List<Student> alleStudentenMitPlz(String plz);
    Student studentLoeschenMitId(Long id) throws StudentNichtGefunden;
}