package at.itkollegimst.studentenverwaltung.controller;

import at.itkollegimst.studentenverwaltung.domain.Student;
import at.itkollegimst.studentenverwaltung.exceptions.StudentNichtGefunden;
import at.itkollegimst.studentenverwaltung.services.StudentenService;
import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
@Controller
@RequestMapping("/web/v1/studenten")
public class StudentThymeleafController {
    private StudentenService StudentenService;


    public StudentThymeleafController(StudentenService StudentenService) {
        this.StudentenService = StudentenService;
    }

    @GetMapping
    public String gibAlleStudenten(Model model) {
        var studenten = this.StudentenService.alleStudenten();
        System.out.println("Anzahl Studenten: " + studenten.size());
        model.addAttribute("allStudents", studenten);
        return "alleStudenten";
    }

    @GetMapping("/insert")
    public String StudentenEinfuegenFormular(Model model) {
        Student student = new Student();
        model.addAttribute("student", student);
        return "studenteneinfuegen";
    }

    @PostMapping("/insert")
    public String studentEinfuegen(@Valid Student student, boolean bindingResult){
        if(bindingResult){
            return "studenteneinfuegen";
        }else{
            this.StudentenService.studentEinfuegen(student);
            return "redirect:/web/v1/studenten";
        }
    }

    @GetMapping("/update/{id}")
    public String studentenUpdatenFormular(@PathVariable Long id, Model model) {
        try {
            Student student = this.StudentenService.studentMitId(id);
            model.addAttribute("student", student);
            return "studentenupdaten";
        } catch (StudentNichtGefunden studentNichtGefunden) {
            return "redirect:/web/v1/studenten";
        }
    }

    @PostMapping("/update")
    public String studentUpdaten(@Valid Student student, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "studentenupdaten";
        } else {
            try {
                this.StudentenService.studentUpdaten(student);
                return "redirect:/web/v1/studenten";
            } catch (StudentNichtGefunden studentNichtGefunden) {
                return "redirect:/web/v1/studenten";
            }
        }
    }

    @GetMapping("/delete/{id}")
    public String studentLoeschen(@PathVariable Long id) {
        try {
            this.StudentenService.studentLoeschenMitId(id);
            return "redirect:/web/v1/studenten";
        } catch (StudentNichtGefunden studentNichtGefunden) {
            return "redirect:/web/v1/studenten";
        }
    }

}

